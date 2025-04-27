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
- **Node.js**: JavaScript runtime for building the Lambda functions
- **TypeScript**: Typed superset of JavaScript for improved developer experience
- **AWS SDK for JavaScript**: Library for interacting with AWS services
- **Jest**: Testing framework for unit and integration tests

### External APIs
- **Microsoft Defender API**: Security service API for retrieving alert information
- **Slack API**: Communication platform API for posting messages to channels

## Development Setup

### Prerequisites
- AWS Account with appropriate permissions
- Node.js (version 18+)
- Terraform (version 1.0+)
- AWS CLI configured with appropriate credentials

### Local Development Environment
- VSCode with recommended extensions:
  - ESLint
  - Terraform
  - AWS Toolkit
- Environment variables configured for local testing
- AWS SAM CLI for local Lambda testing

### CI/CD Pipeline
- GitHub Actions for automated testing and deployment
- Separate environments for development, testing, and production
- Terraform validation and planning in CI pipeline
- Automated tests run before deployment

## Technical Constraints

### AWS Lambda Constraints
- Maximum execution time: 15 minutes (generally not an issue for our use case)
- Maximum deployment package size: 50 MB (compressed)
- Memory allocation: 128 MB to 10 GB (we'll use 256 MB by default)
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
- All API credentials must be stored in AWS Secrets Manager
- All traffic between components must be encrypted (TLS)
- Lambda execution roles must follow principle of least privilege
- API Gateway must validate incoming requests

## Dependencies

### External Dependencies
- Microsoft Azure AD application registration for Defender API access
- Slack workspace and bot configuration
- Domain for API Gateway (if custom domain is required)

### Internal Dependencies
- IAM roles and policies for Lambda execution
- VPC configuration (if Lambda needs VPC access)
- CloudWatch Log Groups for monitoring
- Dead Letter Queues for failed message handling

## Development Workflow

1. Local development and testing
2. Commit changes to feature branch
3. Pull request with code review
4. CI/CD pipeline runs tests and Terraform validation
5. Merge to main branch triggers deployment to development environment
6. Manual promotion to testing and production environments

## Monitoring and Operational Considerations

- CloudWatch Logs for application logging
- CloudWatch Alarms for error rate monitoring
- CloudWatch Dashboards for operational overview
- Automated notifications for system failures
- Regular review of CloudWatch Insights for performance optimization 