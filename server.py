import boto3
import time
import datetime
import json
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base

# Initialize the MCP server
mcp = FastMCP("AWS Incident Response MCP server")

# ---------------------------------------------------
# Tools: Functions to interact with CloudTrail
# ---------------------------------------------------

# initialize athena_table as global variable
athena_table = None

@mcp.tool()
async def cloudtrail_describe_trails() -> list:
    """
    Describe all CloudTrail trails configured in the AWS account.
    """
    try:
        cloudtrail_client = boto3.client('cloudtrail')
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        return trails
    except Exception as e:
        return f"Error describing trails: {str(e)}"

@mcp.tool()
async def cloudtrail_lookup_events(
    aws_region: str, 
    attribute_key: str, 
    attribute_value: str, 
    start_time: str, 
    end_time: str, 
    max_results: int = 50
) -> list:
    """
    Lookup CloudTrail events using filters.

    If the user request falls into one of these scenarios, use the Athena tools instead:
    - EventName is a data event (e.g. GetObject, DeleteObject, PutObject);
    - the user wants to filter by role name;
    - the user wants to filter by principal ID;
    - the user wants to filter by IP address;
    - the user wants to filter by bucket name;
    - the user wants to filter by file object in buckets;
    - the user wants to filter using regex;
    When filtering for EventName, note that the event name is case-sensitive and must match the exact name of the event.
    If you want to use operators like 'equals', 'not equals', 'contains', etc., you must use the Athena tools instead.
    
    <IMPORTANT>
    Call datetime.datetime.now() to get the current date and time before providing the start and end times.
    If the user asks for events happened in the last 7 days, run 'datetime.datetime.now() - datetime.timedelta(days=7)' to get the start date.
    Print out the start and end times to the user.
    </IMPORTANT>

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      attribute_key (str): The name of the event to search for.
        Valid attributes keys: EventId | EventName | ReadOnly | Username | ResourceType | ResourceName | EventSource | AccessKeyId
      attribute_value (str): The value of the event to search for.
        If no key-value pair is provided, use 'ReadOnly'='false'.
      start_time (str): start timestamp with format 'YYYY-MM-DD HH:MM:SS' (e.g. '2025-04-10 12:45:50').
        If not provided, use 'datetime.datetime.now() - datetime.timedelta(days=7)' to get the start date.
      end_time (str): end timestamp with format 'YYYY-MM-DD HH:MM:SS' (e.g. '2025-04-11 12:45:50').
        If not provided, use 'datetime.datetime.now()' to get the end date.
      max_results (int): Maximum number of events to return.

    Returns:
        list: A list of CloudTrail events matching the specified criteria.
    """
    try:
        cloudtrail_client = boto3.client('cloudtrail', region_name=aws_region)
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[{'AttributeKey': attribute_key, 'AttributeValue': attribute_value}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=max_results
        )
        events = response.get('Events', [])
        return [
            {
                'EventId': event.get('EventId'),
                'EventName': event.get('EventName'),
                'EventTime': event.get('EventTime').isoformat() if event.get('EventTime') else None,
                'Username': event.get('Username')
            } for event in events
        ]
    except Exception as e:
        return f"Error looking up events: {str(e)}"

# ---------------------------------------------------
# Tools: Functions to interact with Athena
# ---------------------------------------------------

async def run_athena_query(athena_client, database: str, output_bucket: str, query: str):
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': database},
        ResultConfiguration={'OutputLocation': output_bucket}
    )
    query_execution_id = response['QueryExecutionId']

    # Wait for the query to complete
    max_attempts = 10
    attempts = 0
    while attempts < max_attempts:
        status = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        state = status['QueryExecution']['Status']['State']
        if state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
            break
        time.sleep(3)
        attempts += 1
    if state != 'SUCCEEDED':
        raise Exception(f"Athena query {query_execution_id} did not succeed; state: {state}")
    
    # Retrieve query results
    results_paginator = athena_client.get_paginator('get_query_results')
    result_rows = []
    for page in results_paginator.paginate(QueryExecutionId=query_execution_id):
        result_rows.extend(page['ResultSet']['Rows'])
    # Check if there are results
    if len(result_rows) < 2:
        return "No results found."
    # Extract the header and data
    # Process rows (skipping header row) and convert to JSON
    header = [col['VarCharValue'] for col in result_rows[0]['Data']]
    data = []
    for row in result_rows[1:]:
        row_data = {}
        for idx, col in enumerate(row['Data']):
            row_data[header[idx]] = col.get('VarCharValue', '')
        data.append(row_data)
    return json.dumps(data, indent=2)

def get_organization_details():
    """
    Returns the Organization object from AWS Organizations.
    """
    client = boto3.client('organizations')
    resp = client.describe_organization()
    return resp['Organization']

@mcp.tool()
async def athena_create_cloudtrail_table(
    cloudtrail_bucket: str,
    is_org_trail: bool,
    account_id: str,
    output_bucket: str,
    output_region: str,
    partition_region: str,
    database: str = "default",
) -> str:
    """
    Create an Athena table for CloudTrail logs with partition projection.

    <IMPORTANT>
    Before using this tool ask the user for OUTPUT bucket, unless it is provided.
    This is necessary to create the table correctly. If the API fails, interrupt the process and ask the user for the OUTPUT BUCKET.
    </IMPORTANT>

    Parameters:
      cloudtrail_bucket (str): The S3 bucket for CloudTrail logs - you can retrieve it using the 'cloudtrail_describe_trails' tool.
      is_org_trail (bool): Indicates if the trail is for the organization.
      account_id (str): Your AWS account ID - you can retrieve it.
      output_bucket (str): Ask the user if not specified, S3 bucket URI (e.g. 's3://my-athena-query-results/') for query results - different from cloudtrail_bucket.
      output_region (str): The AWS region for the output bucket - use 'us-east-1' if not specified.
      partition_region (str): The region of the events to be queried. It is used to create the S3 path for the Athena table.
      database (str): Athena database name to be used.

    Returns:
      str: An empty result if successful, or an error message if there was an issue.
    """

    # craft the Athena table name with date+hour suffix
    current_time = datetime.datetime.now()
    date_hour_suffix = current_time.strftime("%Y%m%d_%H%M")
    global athena_table
    athena_table = f"cloudtrail_logs_pp_{date_hour_suffix}"  # Athena table name with date+hour suffix

    # Get the organization ID if the trail is for the organization.
    if is_org_trail:
        org_id = get_organization_details().get('Id')
        trail_location = f's3://{cloudtrail_bucket}/AWSLogs/{org_id}/{account_id}/CloudTrail/{partition_region}/'
    else:
        trail_location = f's3://{cloudtrail_bucket}/AWSLogs/{account_id}/CloudTrail/{partition_region}/'

    # Set the start date for partition projection.
    start_date = (datetime.datetime.now() - datetime.timedelta(days=10)).strftime("%Y/%m/%d") # Format: yyyy/MM/dd, 10 days ago
    
    # Construct the CREATE TABLE query with partition projection.
    query = f"""
CREATE EXTERNAL TABLE {athena_table}(
    eventversion STRING,
    useridentity STRUCT<
        type: STRING,
        principalid: STRING,
        arn: STRING,
        accountid: STRING,
        invokedby: STRING,
        accesskeyid: STRING,
        username: STRING,
        onbehalfof: STRUCT<
             userid: STRING,
             identitystorearn: STRING>,
        sessioncontext: STRUCT<
            attributes: STRUCT<
                mfaauthenticated: STRING,
                creationdate: STRING>,
            sessionissuer: STRUCT<
                type: STRING,
                principalid: STRING,
                arn: STRING,
                accountid: STRING,
                username: STRING>,
            ec2roledelivery:STRING,
            webidfederationdata: STRUCT<
                federatedprovider: STRING,
                attributes: map<string,string>>
        >
    >,
    eventtime STRING,
    eventsource STRING,
    eventname STRING,
    awsregion STRING,
    sourceipaddress STRING,
    useragent STRING,
    errorcode STRING,
    errormessage STRING,
    requestparameters STRING,
    responseelements STRING,
    additionaleventdata STRING,
    requestid STRING,
    eventid STRING,
    readonly STRING,
    resources ARRAY<STRUCT<
        arn: STRING,
        accountid: STRING,
        type: STRING>>,
    eventtype STRING,
    apiversion STRING,
    recipientaccountid STRING,
    serviceeventdetails STRING,
    sharedeventid STRING,
    vpcendpointid STRING,
    vpcendpointaccountid STRING,
    eventcategory STRING,
    addendum STRUCT<
      reason:STRING,
      updatedfields:STRING,
      originalrequestid:STRING,
      originaleventid:STRING>,
    sessioncredentialfromconsole STRING,
    edgedevicedetails STRING,
    tlsdetails STRUCT<
      tlsversion:STRING,
      ciphersuite:STRING,
      clientprovidedhostheader:STRING>
  )
PARTITIONED BY (
   `timestamp` string)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION '{trail_location}'
TBLPROPERTIES (
  'projection.enabled'='true', 
  'projection.timestamp.format'='yyyy/MM/dd', 
  'projection.timestamp.interval'='1', 
  'projection.timestamp.interval.unit'='DAYS', 
  'projection.timestamp.range'='{start_date},NOW', 
  'projection.timestamp.type'='date', 
  'storage.location.template'='{trail_location}/${{timestamp}}')
"""
    try:
        athena_client = boto3.client('athena', region_name=output_region)
        result = await run_athena_query(athena_client, database, output_bucket, query)
        return result
    except Exception as e:
        return f"Error creating Athena table: {str(e)}"


@mcp.tool()
async def athena_query_events(
    aws_region: str,
    start_time: str, 
    end_time: str, 
    database: str,
    output_bucket: str,
    event_names: list,
    principal_id: str = None,
    user_arn: str = None,
    user_name: str = None,
    role_name: str = None,
    ip_address: str = None,
    bucket_name: str = None,
    limit: int = 50,
) -> str:
    """
    Query Athena for granular granular searches on CloudTrail logs.
    
    <IMPORTANT>
    Before calling this tool, you must call the athena_create_cloudtrail_table tool to create the table.
    If the user asks for a different region, you must call the athena_create_cloudtrail_table tool to create the table in that region.
    </IMPORTANT>

    Parameters:
      aws_region: The AWS region - use 'us-east-1' if not specified.
      start_time: ISO string of the start time
      end_time: ISO string of the end time
      database: Athena database name to be used - use 'default' if not specified.
      output_bucket: S3 bucket URI (e.g. 's3://my-athena-query-results/') for query results - different from cloudtrail_bucket.
      event_names: List of event names to filter on (e.g. ["GetObject", "DeleteObject"])
      principal_id: Optional principal ID to filter on. Use the percent sign (%) as a wildcard character.
      user_arn: Optional user ARN to filter on. Use the percent sign (%) as a wildcard character. This is the ARN of the user performing the action.
      user_name: Optional user name to filter on. This is the name of the user performing the action.
      role_name: Optional role name to filter on. This is the name of the role assumed by the user performing the action.
      ip_address: Optional IP address to filter on. Use the percent sign (%) as a wildcard character. This is the IP address of the user performing the action.
      bucket_name: Optional bucket name to filter on. Use the percent sign (%) as a wildcard character.
      limit: Maximum number of results to return (default is 50).

    Returns:
      str: JSON-formatted result of the Athena query.
    """
    # Construct an SQL query
    event_filter = ", ".join([f"'{name}'" for name in event_names])
    events_comment = session_comment = principal_comment = ip_comment = bucket_comment = user_comment = arn_comment = "--"
    if event_names:
        events_comment = ""
    if role_name:
        session_comment = ""
    if principal_id:
        principal_comment = ""
    if user_arn:
        arn_comment = ""
    if user_name:
        user_comment = ""
    if ip_address:
        ip_comment = ""
    if bucket_name:
        bucket_comment = ""
            
    try:
        # Convert ISO format timestamps to Athena-compatible format
        start_dt = datetime.datetime.fromisoformat(start_time.replace('T', ' ').replace('Z', ''))
        end_dt = datetime.datetime.fromisoformat(end_time.replace('T', ' ').replace('Z', ''))
        
        query = f"""
        WITH flat_logs AS (
            SELECT
                eventTime,
                eventName,
                userIdentity.principalId,
                userIdentity.arn,
                userIdentity.userName,
                userIdentity.sessionContext.sessionIssuer.userName as sessionUserName,
                sourceIPAddress,
                eventSource,
                json_extract_scalar(requestParameters, '$.bucketName') as bucketName,
                json_extract_scalar(requestParameters, '$.key') as object
            FROM {athena_table}
        )
        SELECT *
        FROM flat_logs
        WHERE date(from_iso8601_timestamp(eventTime)) BETWEEN timestamp '{start_dt}' AND timestamp '{end_dt}'
        {events_comment}AND eventName IN ({event_filter})
        {user_comment}AND userName = '{user_name}'
        {session_comment}AND sessionUserName = '{role_name}'
        {principal_comment}AND principalId LIKE '{principal_id}'
        {arn_comment}AND arn LIKE '{user_arn}'
        {ip_comment}AND sourceIPAddress LIKE '{ip_address}' 
        {bucket_comment}AND bucketName LIKE '{bucket_name}' 
        LIMIT {limit};
        """
    except ValueError as e:
        return f"Error processing timestamp formats: {str(e)}"
    try:
        athena_client = boto3.client('athena', region_name=aws_region)
        result = await run_athena_query(athena_client, database, output_bucket, query)
    except Exception as e:
        return f"Error querying Athena: {str(e)}"
    return result


# ---------------------------------------------------
# Tools: Functions to interact with CloudWatch
# ---------------------------------------------------

@mcp.tool()
async def cloudwatch_describe_log_groups(
    aws_region: str, 
    log_group_name_pattern: str, 
    limit: int = 50
) -> str:
    """
    Describes available CloudWatch log groups in the specified region.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      log_group_name_pattern (str): The pattern to filter log group names.
        Pattern: [\.\-_/#A-Za-z0-9]*
        If you specify a string for this parameter, the operation returns only log groups that have names that match the string based on a case-sensitive substring search. 
        For example, if you specify Foo, log groups named FooBar, aws/Foo, and GroupFoo would match, but foo, F/o/o and Froo would not match.
        Thus, if you don't find any results with uppercase letters, try using lowercase letters.

    Returns:
      str: JSON-formatted list of log groups.
    """
    try:
        cw_client = boto3.client('logs', region_name=aws_region)
        # Describe log groups (you can add pagination if necessary)
        response = cw_client.describe_log_groups(logGroupNamePattern=log_group_name_pattern, limit=limit)
        log_groups = response.get('logGroups', [])

        if not log_groups:
            return "No log groups found."
        return json.dumps(log_groups, indent=2)
    except Exception as e:
        return f"Error describing log groups: {str(e)}"

@mcp.tool()
async def cloudwatch_list_log_streams(
    aws_region: str, 
    log_group: str, 
    limit: int = 50
) -> str:
    """
    Lists log streams in a specified CloudWatch log group.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      log_group (str): The name of the log group.
      limit (int): Maximum number of log streams to return.

    Returns:
      str: JSON-formatted list of log streams.
    """
    try:
        cw_client = boto3.client('logs', region_name=aws_region)
        response = cw_client.describe_log_streams(logGroupName=log_group, limit=limit)
        log_streams = response.get('logStreams', [])
        return json.dumps(log_streams, indent=2)
    except Exception as e:
        return f"Error listing log streams: {str(e)}"

@mcp.tool()
async def cloudwatch_filter_log_events(
    aws_region: str,
    log_group: str,
    start_time: str,
    end_time: str,
    filter_pattern: str = "",
    limit: int = 20
) -> str:
    """
    Filters log events in a specified CloudWatch log group using FilterLogEvents API.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      log_group (str): The name of the log group.
      start_time (str): ISO formatted start timestamp (e.g. '2025-04-10T00:00:00Z').
      end_time (str): ISO formatted end timestamp (e.g. '2025-04-11T00:00:00Z').
      filter_pattern (str): A filter pattern to match events.
      limit (int): Maximum number of log events to return.

    **Supported regex syntax:**
      - When using regex to search and filter log data, you must surround your expressions with %.
      - Filter patterns with regex can only include the following:
      - Alphanumeric characters - An alphanumeric character is a character that is either a letter (from A to Z or a to z) or a digit (from 0 to 9).
      - Supported symbol characters - These include: '_', '#', '=', '@','/', ';', ',', and '-'. For example, %something!% would be rejected since '!' is not supported.
      - Supported operators - These include: '^', '$', '?', '[', ']', '{', '}', '|', '\', '*', '+', and '.'.
      - The ( and ) operators are not supported. You cannot use parentheses to define a subpattern.
      - Multi-byte characters are not supported.

    Returns:
      str: JSON-formatted list of matching log events.
    """
    try:
        # Convert ISO timestamps to epoch in milliseconds (CloudWatch expects ms)
        start_dt = datetime.datetime.fromisoformat(start_time.replace("T", " ").replace("Z", ""))
        end_dt = datetime.datetime.fromisoformat(end_time.replace("T", " ").replace("Z", ""))
        start_epoch_ms = int(start_dt.timestamp() * 1000)
        end_epoch_ms = int(end_dt.timestamp() * 1000)
    except ValueError as ve:
        return f"Error processing timestamp formats: {str(ve)}"
    
    try:
        cw_client = boto3.client('logs', region_name=aws_region)
        response = cw_client.filter_log_events(
            logGroupName=log_group,
            startTime=start_epoch_ms,
            endTime=end_epoch_ms,
            filterPattern=filter_pattern,
            limit=limit,
            unmask=True
        )
        events = response.get('events', [])
        return json.dumps(events, indent=2)
    except Exception as e:
        return f"Error filtering log events: {str(e)}"

@mcp.tool()
async def ec2_describe_flow_logs(
    aws_region: str,
    flow_log_ids: list[str] = None,
    resource_ids: list[str] = None,
    resource_type: str = None,
    max_results: int = 10
) -> str:
    """
    Describe one or more VPC Flow Logs.
    If no filter is provided, returns all Flow Logs in the region.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      flow_log_ids (list[str], optional): List of Flow Log IDs to describe.
      resource_ids (list[str], optional): List of resource IDs to filter by.
      resource_type (str, optional): Type of resource to filter by (e.g. 'VPC', 'NetworkInterface', 'Subnet').
      max_results (int, optional): Maximum number of results to return.

    Returns:
        str: JSON-formatted list of Flow Logs.
    """
    client = boto3.client('ec2', region_name=aws_region)
    params = {}
    if flow_log_ids:
        params["FlowLogIds"] = flow_log_ids
    if resource_ids:
        params["Filter"] = params.get("Filter", []) + [{
            "Name": "resource-id",
            "Values": resource_ids,
            "MaxResults": max_results
        }]
    if resource_type:
        params["Filter"] = params.get("Filter", []) + [{
            "Name": "resource-type",
            "Values": [resource_type]
        }]
    resp = client.describe_flow_logs(**params)
    return json.dumps(resp.get("FlowLogs", []), indent=2, cls=DateTimeEncoder)

# --------------------------------------------------------------------------
# Tools: Functions to interact with GuardDuty
# --------------------------------------------------------------------------

@mcp.tool()
async def guardduty_list_detectors(aws_region: str) -> str:
    """
    List all GuardDuty detector IDs in the specified AWS region.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.

    Returns:
      str: JSON-formatted list of detector IDs.
    """
    try:
        client = boto3.client('guardduty', region_name=aws_region)
        response = client.list_detectors()
        detectors = response.get("DetectorIds", [])
        return json.dumps(detectors, indent=2)
    except Exception as e:
        return f"Error listing GuardDuty detectors: {str(e)}"

@mcp.tool()
async def guardduty_list_findings(
    aws_region: str,
    detector_id: str,
    finding_ids: list = None,
    severity_threshold: float = None
) -> str:
    """
    List GuardDuty finding IDs for a given detector.
    
    Optionally, you can supply a list of finding IDs to retrieve specific findings or a minimum severity threshold to filter findings.
    
    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      detector_id (str): The GuardDuty detector ID.
      finding_ids (list, optional): Specific finding IDs to query.
      severity_threshold (float, optional): If provided, returns only findings with severity greater than this value.
    
    <IMPORTANT>
    After calling this tool, you should call guardduty_get_findings multiple times with the finding_ids returned by this tool.
    </IMPORTANT>

    Returns:
      str: JSON-formatted list of finding IDs.
    """
    try:
        client = boto3.client('guardduty', region_name=aws_region)
        params = {}
        if finding_ids:
            params["FindingIds"] = finding_ids
        if severity_threshold is not None:
            # Apply a filter criterion for severity greater than the threshold.
            params["FindingCriteria"] = {
                "Criterion": {
                    "severity": {
                        "Gt": int(severity_threshold)
                    }
                }
            }
        response = client.list_findings(
            DetectorId=detector_id,
            **params
        )
        findings = response.get("FindingIds", [])
        return json.dumps(findings, indent=2)
    except Exception as e:
        return f"Error listing GuardDuty findings: {str(e)}"

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime.datetime):
            return o.isoformat()  # Convert datetime to ISO-format string.
        return super().default(o)
    
@mcp.tool()
async def guardduty_get_findings(
    aws_region: str,
    detector_id: str,
    finding_ids: list
) -> str:
    """
    Get detailed information for the specified GuardDuty findings.
    
    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      detector_id (str): The GuardDuty detector ID.
      finding_ids (list): A list of finding IDs for which to retrieve details.
    
    <IMPORTANT>
    The server may crash when the response is too large. To avoid this, pass only max 2 finding IDs at a time. 
    The finding_ids list should contain a maximum of 2 IDs.
    If guardduty_list_findings returns more than 2 IDs, you should call this tool max 5 times. 
    Then, proceed with your analysis, but remember to notify the user that there may be additional findings not retrieved.
    </IMPORTANT>

    Returns:
      str: JSON-formatted details of the findings.
    """
    try:
        client = boto3.client('guardduty', region_name=aws_region)
        response = client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )
        findings = response.get("Findings", [])
        # insert sleep of 3 seconds to avoid throttling
        #time.sleep(3)
        return json.dumps(findings, indent=2, cls=DateTimeEncoder)
    except Exception as e:
        return f"Error getting GuardDuty findings: {str(e)}"

@mcp.tool()
async def guardduty_get_finding_statistics(aws_region: str, detector_id: str) -> str:
    """
    Get summary statistics for GuardDuty findings for a given detector.
    
    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      detector_id (str): The GuardDuty detector ID.
    
    Returns:
      str: JSON-formatted statistics about the findings.
    """
    try:
        client = boto3.client('guardduty', region_name=aws_region)
        response = client.get_findings_statistics(
            DetectorId=detector_id,
            FindingStatisticTypes=['COUNT_BY_SEVERITY'],
            FindingCriteria={}
        )
        statistics = response.get("FindingStatistics", {})
        return json.dumps(statistics, indent=2)
    except Exception as e:
        return f"Error getting GuardDuty finding statistics: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# Tools: Functions to interact with AWS Config
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
async def config_describe_recorder_status(aws_region: str) -> str:
    """
    Describe status of AWS Config recorder(s).
    
    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.

    Returns:
      JSON list of ConfigurationRecorderStatus objects.
    """
    client = boto3.client('config', region_name=aws_region)
    resp = client.describe_configuration_recorder_status()
    statuses = resp.get("ConfigurationRecorderStatuses", [])
    return json.dumps(statuses, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def config_list_discovered_resources(aws_region: str, resource_type: str) -> str:
    """
    List resource identifiers that AWS Config has discovered.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      resource_type (str): e.g. 'AWS::EC2::Instance'.

    Returns:
      JSON list of resourceIdentifier objects.
    """
    client = boto3.client('config', region_name=aws_region)
    paginator = client.get_paginator('list_discovered_resources')
    all_resources = []
    for page in paginator.paginate(resourceType=resource_type):
        all_resources.extend(page.get('resourceIdentifiers', []))
    return json.dumps(all_resources, indent=2)

@mcp.tool()
def config_get_resource_config_history(
    aws_region: str,
    resource_type: str,
    resource_id: str,
    start_time: str,
    end_time: str,
    limit: int = 10
) -> str:
    """
    Fetch configuration snapshots for a resource between two ISO timestamps.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      resource_type (str): e.g. 'AWS::S3::Bucket'.
      resource_id (str): the resource's ARN or ID.
      start_time (str): ISO timestamp, e.g. '2025-04-01T00:00:00Z'.
      end_time   (str): ISO timestamp.
      limit (int): Maximum number of configuration items to return.

    Returns:
      JSON list of ConfigurationItem objects.
    """
    client = boto3.client('config', region_name=aws_region)
    # Parse ISO timestamps into datetime (with UTC)
    try:
        start_dt = datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_dt   = datetime.datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    except Exception as e:
        return f"Error parsing timestamps: {e}"

    resp = client.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        earlierTime=start_dt,
        laterTime=end_dt,
        limit=limit
    )
    items = resp.get("configurationItems", [])
    return json.dumps(items, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def config_describe_compliance_by_resource(
    aws_region: str,
    resource_type: str = None
) -> str:
    """
    List compliance summaries for resources, optionally filtered by type.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      resource_type (str): optional AWS resource type filter.

    Returns:
      JSON list of ComplianceByResource objects.
    """
    client = boto3.client('config', region_name=aws_region)
    params = {}
    if resource_type:
        params["ResourceType"] = resource_type
    resp = client.describe_compliance_by_resource(**params)
    compliances = resp.get("ComplianceByResources", [])
    return json.dumps(compliances, indent=2)

@mcp.tool()
async def config_describe_config_rules(
    aws_region: str,
    rule_names: list = None
) -> str:
    """
    Describe one or more AWS Config rules, or all rules if none specified.

    Parameters:
      aws_region (str): The AWS region - use 'us-east-1' if not specified.
      rule_names (list): optional list of Config rule names.

    Returns:
      JSON list of ConfigRule objects.
    """
    client = boto3.client('config', region_name=aws_region)
    if rule_names:
        resp = client.describe_config_rules(ConfigRuleNames=rule_names)
    else:
        resp = client.describe_config_rules()
    rules = resp.get("ConfigRules", [])
    return json.dumps(rules, indent=2, cls=DateTimeEncoder)

# --------------------------------------------------------------------------
# Tools: Functions to interact with Network Access Analyzer
# --------------------------------------------------------------------------

@mcp.tool()
async def networkinsights_list_scopes(aws_region: str) -> str:
    """
    Describe all Network Access Scopes in the region.

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.

    Returns:
        JSON list of NetworkInsightsAccessScope objects.
    """
    client = boto3.client('ec2', region_name=aws_region)
    resp = client.describe_network_insights_access_scopes()
    scopes = resp.get('NetworkInsightsAccessScopes', [])
    return json.dumps(scopes, indent=2, cls=DateTimeEncoder)


@mcp.tool()
async def networkinsights_list_analyses(
    aws_region: str,
    scope_id: str = None,
    analysis_ids: list[str] = None
) -> str:
    """
    Describe analyses for one or more scopes.

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.
        scope_id (str): The ID of the access scope to filter by.
        analysis_ids (list[str]): List of analysis IDs to filter by.

    Returns:
        JSON list of NetworkInsightsAccessScopeAnalysis objects.
    """
    client = boto3.client('ec2', region_name=aws_region)
    params = {}
    if scope_id:
        params['NetworkInsightsAccessScopeId'] = scope_id
    if analysis_ids:
        params['NetworkInsightsAccessScopeAnalysisIds'] = analysis_ids
    resp = client.describe_network_insights_access_scope_analyses(**params)
    analyses = resp.get('NetworkInsightsAccessScopeAnalyses', [])
    return json.dumps(analyses, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def networkinsights_get_findings(
    aws_region: str,
    analysis_id: str,
    max_results: int = 1
) -> str:
    """
    Retrieve all findings for a given analysis.

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.
        analysis_id (str): The ID of the analysis to retrieve findings for.
        max_results (int): Maximum number of findings to return.

    Returns:
        JSON list of NetworkInsightsAccessScopeAnalysisFinding objects.
    """
    client = boto3.client('ec2', region_name=aws_region)
    findings = []
    next_token = None
    while True:
        kwargs = {
            'NetworkInsightsAccessScopeAnalysisId': analysis_id,
            'MaxResults': max_results
        }
        if next_token:
            kwargs['NextToken'] = next_token
        resp = client.get_network_insights_access_scope_analysis_findings(**kwargs)
        findings.extend(resp.get('AnalysisFindings', []))
        next_token = resp.get('NextToken')
        if not next_token:
            break
    return json.dumps(findings, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def networkinsights_start_analysis(
    aws_region: str,
    scope_id: str,
    dry_run: bool = False,
    tag_specifications: list[dict] = None,
    client_token: str = None
) -> str:
    """
    Start a Network Access Scope analysis.

    Parameters:
    aws_region (str): AWS region - use 'us-east-1' if not specified.
    scope_id (str): The NetworkInsightsAccessScopeId to analyze.
    dry_run (bool): If True, checks permissions without starting.
    tag_specifications (list): TagSpecification dicts for annotating the analysis.
    client_token (str): Idempotency token for the request.

    Returns:
    str: JSON representation of the NetworkInsightsAccessScopeAnalysis object.
    """
    client = boto3.client('ec2', region_name=aws_region)
    params = {'NetworkInsightsAccessScopeId': scope_id}
    if dry_run:
        params['DryRun'] = True
    if tag_specifications:
        params['TagSpecifications'] = [{
            'ResourceType': 'network-insights-access-scope-analysis',
            'Tags': tag_specifications
        }]
    if client_token:
        params['ClientToken'] = client_token

    response = client.start_network_insights_access_scope_analysis(**params)
    analysis = response.get('NetworkInsightsAccessScopeAnalysis', {})
    return json.dumps(analysis, indent=2, cls=DateTimeEncoder)

# --------------------------------------------------------------------------
# Tools: Functions to interact with IAM Access Analyzer
# --------------------------------------------------------------------------

@mcp.tool()
async def accessanalyzer_list_analyzers(aws_region: str) -> str:
    """
    List all IAM Access Analyzer analyzers in the specified region.

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.

    Returns:
        str: JSON-formatted list of analyzers.
    """
    client = boto3.client('accessanalyzer', region_name=aws_region)
    response = client.list_analyzers()
    analyzers = response.get('analyzers', [])
    return json.dumps(analyzers, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def accessanalyzer_get_analyzer(
    aws_region: str,
    analyzer_name: str
) -> str:
    """
    Retrieve details of a specific analyzer by name.

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.
        analyzer_name (str): The name of the analyzer to retrieve.
    
    Returns:
        str: JSON-formatted details of the analyzer.
    """
    client = boto3.client('accessanalyzer', region_name=aws_region)
    response = client.get_analyzer(analyzerName=analyzer_name)
    analyzer = response.get('analyzer', {})
    return json.dumps(analyzer, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def accessanalyzer_list_findings(
    aws_region: str,
    analyzer_arn: str,
    filter: dict = None,
    max_results: int = 50
) -> str:
    """
    List findings for an analyzer, with optional filter.
    filter: {'resourceType': {'eq': ['AWS::S3::Bucket']}, ...}

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.
        analyzer_arn (str): The ARN of the analyzer to list findings for.
        filter (dict, optional): Filter criteria for findings.
        max_results (int): Maximum number of findings to return.

    Returns:
        str: JSON-formatted list of findings.
    """
    client = boto3.client('accessanalyzer', region_name=aws_region)
    params = {'analyzerArn': analyzer_arn, 'maxResults': max_results}
    if filter:
        params['filter'] = filter
    findings = []
    next_token = None
    while True:
        if next_token:
            params['nextToken'] = next_token
        response = client.list_findings(**params)
        summaries = response.get('findingSummaries', [])
        findings.extend(summaries)
        next_token = response.get('nextToken')
        if not next_token:
            break
    return json.dumps(findings, indent=2, cls=DateTimeEncoder)

@mcp.tool()
async def accessanalyzer_get_finding(
    aws_region: str,
    analyzer_arn: str,
    finding_id: str
) -> str:
    """
    Retrieve detailed information about a single finding.

    Parameters:
        aws_region (str): The AWS region - use 'us-east-1' if not specified.
        analyzer_arn (str): The ARN of the analyzer.
        finding_id (str): The ID of the finding to retrieve.
    
    Returns:
        str: JSON-formatted details of the finding.
    """
    client = boto3.client('accessanalyzer', region_name=aws_region)
    response = client.get_finding(analyzerArn=analyzer_arn, id=finding_id)
    finding = response.get('finding', {})
    return json.dumps(finding, indent=2, cls=DateTimeEncoder)

# ---------------------------------------------------
# Prompts: Templates for common log analysis tasks
# ---------------------------------------------------

# System prompt
@mcp.prompt()
async def system_concise() -> list[base.Message]:
    return [ base.UserMessage("You are an AWS Incident Response assistant. When answering user requests, skip the preamble, "
                                "keep your response terse and write only the bare bones necessary information.") ]

# CloudTrail
@mcp.prompt()
async def analyze_suspicious_activity() -> str:
    """
    Provide a prompt for analyzing CloudTrail log entries for indicators of suspicious activity.
    """
    return (
        "Analyze the following CloudTrail log entries for suspicious activity. Look for "
        "unusual login attempts, unauthorized API calls, or anomalies in service usage. Provide a brief summary "
        "of any findings and recommend further investigation steps."
    )

@mcp.prompt()
async def explain_event_details(event_log: str) -> str:
    """
    Given a specific CloudTrail event log entry (as text), explain its details.
    
    Parameters:
      event_log (str): The raw log data to be explained.
    """
    return (
        f"Please explain the following CloudTrail event log entry in detail, highlighting the key attributes, "
        f"what they indicate, and any potential security implications:\n\n{event_log}"
    )

# Athena
@mcp.prompt()
async def analyze_athena_query_results(results: str) -> str:
    """
    Given the raw results of an Athena query, identify any
    patterns of unusual data access (e.g. spikes in GetObject/DeleteObject
    calls, unexpected source IPs), summarize key findings, and suggest next steps.
    
    Parameters:
      results (str): The Athena query output as a formatted table or JSON.
    """
    return (
        f"Analyze the following Athena query results. "
        f"Look for anomalies such as unusually frequent object accesses, "
        f"deletions, or access from unfamiliar locations. Provide a concise "
        f"summary of any suspicious patterns and recommend further investigation steps:\n\n{results}"
    )

# CloudWatch Logs
@mcp.prompt()
async def interpret_cloudwatch_logs(log_entries: str) -> str:
    """
    Given a set of CloudWatch log entries, detect errors, warnings, or
    anomalous messages that could indicate security issues or system failures.
    Summarize the root causes and recommend remediation or escalation steps.
    
    Parameters:
      log_entries (str): The raw log lines or JSON from CloudWatch.
    """
    return (
        f"Please review the following CloudWatch log entries. Identify any "
        f"errors, warnings, or unexpected behaviors that might signal security "
        f"incidents or system faults. Provide a brief analysis of root causes "
        f"and recommended remediation actions:\n\n{log_entries}"
    )

# GuardDuty
@mcp.prompt()
async def summarize_guardduty_findings(findings: str) -> str:
    """
    Summarize a list of GuardDuty findings, grouping by severity and type.
    Highlight the most critical alerts, explain what they mean, and suggest
    priority response actions.
    
    Parameters:
      findings (str): JSON or table of GuardDuty finding summaries.
    """
    return (
        f"Here are GuardDuty findings to review. Group them by severity and "
        f"finding type, highlight the top 3 most critical alerts, explain their "
        f"security implications, and outline recommended response steps:\n\n{findings}"
    )

# AWS Config
@mcp.prompt()
async def summarize_config_compliance(compliance_data: str) -> str:
    """
    Given AWS Config compliance summaries, identify non-compliant resources,
    explain the violated rules, and recommend corrective actions to achieve
    compliance.
    
    Parameters:
      compliance_data (str): JSON list of ComplianceByResource objects.
    """
    return (
        f"Analyze the following AWS Config compliance data. Identify which "
        f"resources are non-compliant, describe the specific rules they violate, "
        f"and provide concise remediation steps to bring them into compliance:\n\n{compliance_data}"
    )

# VPC Flow Logs
@mcp.prompt()
async def analyze_vpc_flow_logs(flow_log_data: str) -> str:
    """
    Analyze VPC Flow Logs for signs of lateral movement, data exfiltration,
    or unusual traffic patterns. Summarize any suspicious IP pairs or ports
    that warrant further investigation.
    
    Parameters:
      flow_log_data (str): Raw flow log records (CSV or JSON).
    """
    return (
        f"Review these VPC Flow Log records. Look for anomalous traffic such as "
        f"large outbound data transfers, connections on unusual ports, or "
        f"communication between unexpected subnets. Summarize any red flags "
        f"and suggest next steps:\n\n{flow_log_data}"
    )

# Network Access Analyzer
@mcp.prompt()
async def interpret_network_access_analysis(analysis_report: str) -> str:
    """
    Given the findings from a Network Access Analyzer scope analysis, explain
    which paths are reachable or blocked, identify any misconfigurations
    (security groups, NACLs, route tables), and recommend configuration changes.
    
    Parameters:
      analysis_report (str): JSON or tabular analysis of reachability paths.
    """
    return (
        f"Here is a Network Access Analyzer report. For each source-destination "
        f"pair, state whether the path is reachable or blocked, highlight any "
        f"security group or NACL rules that cause blockages, and recommend "
        f"configuration adjustments to achieve desired connectivity:\n\n{analysis_report}"
    )

# IAM Access Analyzer
@mcp.prompt()
async def review_iam_access_findings(finding_summaries: str) -> str:
    """
    Review IAM Access Analyzer findings for resource-based and identity-based
    policy issues. Identify permissions that are overly permissive or allow
    unintended access, and suggest least-privilege policy fixes.
    
    Parameters:
      finding_summaries (str): List or JSON of Access Analyzer finding summaries.
    """
    return (
        f"Analyze the following IAM Access Analyzer findings. Identify any "
        f"overly permissive permissions or unintended resource access, explain "
        f"the associated risks, and propose least-privilege policy changes:\n\n{finding_summaries}"
    )

# ---------------------------------------------------
# Running the Server
# ---------------------------------------------------

if __name__ == "__main__":
    mcp.run()
