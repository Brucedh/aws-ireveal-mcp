# AWS‑IReveal‑MCP

**AWS‑IReveal‑MCP** is a Model Context Protocol (MCP) server designed to give security teams and incident responders a unified interface to AWS services useful for investigation. By connecting AWS‑IReveal‑MCP to any MCP client (such as Claude Desktop or Cline), you can invoke queries and analyses across multiple AWS services without leaving your LLM‑driven workspace.

## Features

AWS‑IReveal‑MCP integrates with the following AWS services and functionalities:

- **CloudTrail** — Management event logs for API activity  
- **Amazon Athena** — SQL queries over CloudTrail logs  
- **CloudWatch** — Operational logs and ad hoc analysis  
- **Amazon GuardDuty** — Threat detection and finding investigation  
- **AWS Config** — Resource configuration history and compliance status  
- **VPC Flow Logs** — Network traffic metadata for forensic analysis  
- **Network Access Analyzer** — Reachability checks across SG/NACL/VPC  
- **IAM Access Analyzer** — Policy and resource‑based access findings  

Together, these services let you  
- Trace “who did what, when, and where” (CloudTrail, Config)  
- Examine detailed data events (Athena)  
- Search and visualize logs (CloudWatch, VPC Flow Logs)  
- Surface security alerts (GuardDuty, IAM Access Analyzer)  
- Verify network reachability and configuration (Network Access Analyzer)  

### Example Prompts

- analyze activity by IP x.x.x.x in the last 5 days
- analyze activity by role 'sysadmin' in the last 24 hours
- investigate suspicious activity on cloudtrail in the last 7 days on us-west-2
- is there any data event on buckets with name containing 'customers' in the last 7 days?
- investigate cloudwatch logs related to Bedrock
- propose remediations for GuardDuty findings with high risk happened in the last 2 days
- identify non-compliant resources, explain violated rules, and suggest remediation

## Installation

### Prerequisites

- Python 3
- MCP Python SDK (`mcp[cli]`)  
- `boto3` (AWS SDK for Python)  
- AWS credentials configured

### Configuration
Add the following configuration to your MCP client's settings file:

```
{
  "mcpServers": {
    "aws-ireveal": {
      "command": "uv",
      "args": [
        "run",
        "/path/to/aws-ireveal-mcp/server.py"
      ],
      "env": {
        "AWS_PROFILE": "<YOUR_PROFILE>"
      }
    }
  }
}
```