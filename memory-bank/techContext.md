# Technical Context

## Technologies Used

### Cloud Services
- **AWS Lambda**: Serverless compute service for running code without provisioning servers
- **AWS API Gateway**: Service for creating, publishing, and managing APIs
- **AWS CloudWatch**: Monitoring and observability service for resources and applications
- **AWS Secrets Manager**: Service for storing and managing secrets securely
- **AWS EventBridge**: Serverless event bus for building event-driven applications

### Infrastructure as Code
- **Terraform**: Tool for building, changing, and versioning infrastructure safely and efficiently
- **AWS Provider for Terraform**: Provider that exposes AWS resources
- **Terraform S3 Backend**: Remote state storage to enable team collaboration

### Programming Languages and Frameworks
- **Python**: Programming language for building the Lambda functions
- **Boto3**: AWS SDK for Python
- **Requests**: HTTP library for Python
- **pytest**: Testing framework for unit and integration tests

### External APIs
- **Microsoft Defender API**: Security service API for retrieving alert information
- **Slack API**: Communication platform API for posting messages to channels

## API References

### Microsoft Defender API
- **API Documentation**: [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro)
- **Key Endpoints**:
  - `/api/alerts`: Retrieve security alerts
  - `/api/incidents`: Retrieve security incidents
  - `/api/machines`: Retrieve machine information
- **Authentication**: OAuth 2.0 with Azure AD
- **API Version**: v1.0
- **Rate Limits**: Throttling may apply based on tenant size and subscription

### Slack API
- **API Documentation**: [Slack API](https://api.slack.com/web)
- **Key Endpoints**:
  - `chat.postMessage`: Send messages to a channel
  - `chat.update`: Update a message
  - `files.upload`: Upload files to a channel
- **Authentication**: Bearer token authentication
- **Block Kit**: [Block Kit Builder](https://app.slack.com/block-kit-builder) for message formatting
- **Rate Limits**: Tier-based; generally 1 message per second

## Development Setup

### Prerequisites
- AWS Account with appropriate permissions
- Python (version 3.9+)
- Terraform (version 1.0+)
- AWS CLI configured with appropriate credentials

### Local Development Environment
- VSCode with recommended extensions:
  - Python
  - Terraform
  - AWS Toolkit
- Environment variables configured for local testing
- AWS SAM CLI for local Lambda testing

### CI/CD Pipeline
- GitHub Actions for automated testing and deployment (planned)
- Separate environments for development, testing, and production
- Terraform validation and planning in CI pipeline
- Automated tests run before deployment

## Technical Constraints

### AWS Lambda Constraints
- Maximum execution time: 15 minutes (generally not an issue for our use case)
- Maximum deployment package size: 50 MB (compressed)
- Memory allocation: 128 MB to 10 GB (using 256 MB for our functions)
- Cold start latency: First-time function invocation may have higher latency

### API Limitations
- **Microsoft Defender API**:
  - Rate limiting: Check documentation for current limits
  - Authentication: OAuth 2.0 with client credentials flow
  - Historical data access: Limited to 30 days by default

- **Slack API**:
  - Rate limiting: Tier-based; generally 1 message per second
  - Message formatting: Limited to Block Kit formatting options
  - Attachment limits: Maximum of 100 attachments per message

### Security Requirements
- All API credentials stored in AWS Secrets Manager
- All traffic between components encrypted (TLS)
- Lambda execution roles follow principle of least privilege
- API Gateway validates incoming requests

## Dependencies

### External Dependencies
- Microsoft Azure AD application registration for Defender API access
- Slack workspace and bot configuration
- Domain for API Gateway (if custom domain is required)

### Internal Dependencies
- IAM roles and policies for Lambda execution
- CloudWatch Log Groups for monitoring
- Dead Letter Queues for failed message handling (not yet implemented)

## Implementation Details

### Alert Processing
- **Webhook Endpoint**: API Gateway receives alerts from Microsoft Defender
- **Alert Processing Function**: Parses, filters, and formats alerts for Slack
- **Severity Filtering**: Focuses on high and critical severity alerts
- **Error Handling**: Structured error handling with detailed logging

### Summary Reporting
- **Scheduled Execution**: EventBridge triggers Lambda at 9:00 AM on weekdays
- **Time Range Logic**: 72 hours for Monday reports, 24 hours for other weekdays
- **Defender API Client**: Retrieves historical alerts based on time range
- **Summary Formatting**: Creates structured Slack messages with alert details

### Message Formatting
- **Slack Block Kit**: Used for rich message formatting
- **Alert Formatting**: Highlights severity, affected resources, and threat details
- **Summary Formatting**: Groups alerts by category with overview statistics

## Monitoring and Operational Considerations

- CloudWatch Logs for application logging
- Structured logging with severity levels
- Error tracking in CloudWatch
- Future improvement: CloudWatch Dashboards for operational overview
- Future improvement: Automated notifications for system failures 