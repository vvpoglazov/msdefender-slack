# System Patterns

## System Architecture

The system follows a serverless, event-driven architecture based on AWS services:

```
                                      ┌─────────────────┐
                                      │                 │
                                      │  AWS Secrets    │
                                      │    Manager      │
                                      │                 │
                                      └─────┬───────────┘
                                            │
                                            │ API Keys
                                            │
┌─────────────────┐    ┌─────────────┐    ┌▼───────────────┐    ┌─────────────┐
│                 │    │             │    │                 │    │             │
│    Microsoft    │    │  AWS API    │    │  AWS Lambda     │    │  Slack      │
│    Defender     ├───►│  Gateway    ├───►│  (Alert         ├───►│  Channels   │
│                 │    │             │    │   Processor)    │    │             │
└─────────────────┘    └─────────────┘    └─────────────────┘    └─────────────┘
                                                  ▲
                                                  │
┌─────────────────┐    ┌─────────────┐            │
│                 │    │             │            │
│  AWS            │    │  AWS Lambda │            │
│  EventBridge    ├───►│  (Summary   ├────────────┘
│                 │    │   Generator)│
└─────────────────┘    └─────────────┘
```

## Key Technical Decisions

1. **Serverless Architecture**: Using AWS Lambda to eliminate the need for managing servers and provide automatic scaling.

2. **Infrastructure as Code**: Using Terraform to define and manage infrastructure, ensuring consistency and repeatability across deployments.

3. **Python for Lambda Functions**: Using Python for Lambda functions due to its simplicity and extensive library support, particularly for AWS integration via boto3.

4. **Event-Driven Model**:
   - Webhook events from Microsoft Defender trigger real-time notifications
   - Scheduled events from EventBridge trigger daily summary reports

5. **Separation of Concerns**:
   - Alert Processing Lambda: Handles real-time notifications
   - Summary Generator Lambda: Handles daily report generation
   - Shared libraries for common functionality

6. **Secure Secret Management**: Storing API tokens and credentials in AWS Secrets Manager.

7. **Comprehensive Monitoring**: Using CloudWatch for monitoring, logging, and alerting on system health.

## Design Patterns

1. **Adapter Pattern**: The implementation uses the Adapter pattern in several places:
   - `DefenderClient` adapts the Microsoft Defender API to our application's needs
   - `SlackClient` adapts the Slack API for message delivery
   - `alert_formatter.py` adapts alert data to Slack message format

2. **Strategy Pattern**: Different strategies for handling various alert types:
   - Filtering strategy based on alert severity
   - Different reporting strategies for Monday vs. weekday reports
   - Different formatting strategies based on message type

3. **Factory Pattern**: Message formatting follows a factory-like approach:
   - `format_alert()` creates appropriate message blocks based on alert data
   - `format_summary()` creates report blocks based on alert collection

4. **Decorator Pattern**: The message formatting applies additional context:
   - Adding severity indicators to base messages
   - Enhancing messages with timestamps and resource information
   - Adding categorization to summary reports

5. **Observer Pattern**: The system observes Microsoft Defender events via webhooks.

6. **Dependency Injection**: Lambda functions receive dependencies (like clients) that can be replaced for testing.

## Component Relationships

### Alert Processing Pipeline

1. **Webhook Receiver** (API Gateway):
   - Authenticates incoming requests from Microsoft Defender
   - Routes payload to Alert Processor Lambda

2. **Alert Processor** (Lambda - `alert_processor.py`):
   - Initializes clients and secrets
   - Parses alert data from webhook payload
   - Filters alerts based on severity
   - Calls formatter to create Slack message
   - Delivers formatted message to Slack

3. **Alert Formatter** (`alert_formatter.py`):
   - Creates structured Slack Block Kit messages
   - Applies severity-based formatting
   - Includes relevant alert details
   - Creates actionable message format

### Summary Report Pipeline

1. **Scheduler** (EventBridge):
   - Triggers Summary Generator Lambda at 9:00 AM on working days
   - Uses cron expression for scheduling

2. **Summary Generator** (Lambda - `summary_generator.py`):
   - Determines report type based on day of week
   - Calculates appropriate time range (24 or 72 hours)
   - Retrieves alerts from Microsoft Defender API
   - Filters alerts by severity
   - Calls formatter to create summary report
   - Delivers formatted report to Slack

3. **Summary Formatter** (`summary_formatter.py`):
   - Creates structured summary using Slack Block Kit
   - Categorizes alerts by threat type
   - Provides overview statistics
   - Formats for readability

## Code Organization

The codebase follows a modular structure:

```
src/
├── functions/           # Lambda function handlers
│   ├── alert_processor.py  # Processes real-time alerts
│   └── summary_generator.py  # Generates daily reports
└── lib/                 # Shared library code
    ├── alert_formatter.py   # Formats alerts for Slack
    ├── defender_client.py   # Microsoft Defender API client
    ├── secret_manager.py    # Handles AWS Secrets Manager
    ├── slack_client.py      # Slack API client
    └── summary_formatter.py # Formats summary reports
```

This organization allows for:
- Clear separation of concerns
- Reusability of common code
- Easier testing of individual components
- Better maintainability

## Error Handling Strategy

1. **Structured Exception Handling**: Try-except blocks with specific exception handling.

2. **Comprehensive Logging**: Detailed logging for debugging and troubleshooting.

3. **Graceful Degradation**: If non-critical components fail, the system continues operation.

4. **Future Improvements**:
   - Dead Letter Queues for capturing failed messages
   - Retry mechanisms for transient failures
   - Fallback notification paths for critical errors

## Scalability Considerations

1. **Lambda Auto-scaling**: Functions automatically scale with load.

2. **API Gateway Throttling**: Can be configured to control request rates.

3. **Slack Rate Limits**: Message delivery respects Slack API limits. 