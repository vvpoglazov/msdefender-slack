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

3. **Event-Driven Model**:
   - Webhook events from Microsoft Defender trigger real-time notifications
   - Scheduled events from EventBridge trigger daily summary reports

4. **Separation of Concerns**:
   - Alert Processing Lambda: Handles real-time notifications
   - Summary Generator Lambda: Handles daily report generation

5. **Secure Secret Management**: Storing API tokens and credentials in AWS Secrets Manager.

6. **Comprehensive Monitoring**: Using CloudWatch for monitoring, logging, and alerting on system health.

## Design Patterns

1. **Adapter Pattern**: Converting Microsoft Defender alert formats to Slack message formats.

2. **Strategy Pattern**: Different strategies for handling various alert types and severities.

3. **Factory Pattern**: Creating appropriate message templates based on alert type.

4. **Decorator Pattern**: Enhancing basic messages with severity indicators and additional context.

5. **Observer Pattern**: The system observes (listens to) Microsoft Defender events and reacts accordingly.

## Component Relationships

### Alert Processing Pipeline

1. **Webhook Receiver** (API Gateway):
   - Authenticates incoming requests
   - Validates payload structure
   - Routes to Lambda function

2. **Alert Processor** (Lambda):
   - Parses alert data
   - Filters based on severity
   - Formats for Slack
   - Delivers to Slack API

3. **Notification Formatter**:
   - Applies message templates
   - Adds severity indicators
   - Includes relevant details
   - Creates actionable message format

### Summary Report Pipeline

1. **Scheduler** (EventBridge):
   - Triggers at 9:00 AM on working days
   - Determines report type (Monday or weekday)

2. **Summary Generator** (Lambda):
   - Queries Microsoft Defender API for historical alerts
   - Aggregates and categorizes threats
   - Generates summary statistics
   - Creates formatted report

3. **Report Formatter**:
   - Creates structured summary
   - Formats for readability
   - Categorizes by threat type
   - Highlights critical issues

## Error Handling Strategy

1. **Retry Logic**: Automatic retries for transient failures.

2. **Dead Letter Queues**: Capturing failed messages for troubleshooting.

3. **Fallback Mechanisms**: Alternate notification paths if primary fails.

4. **Comprehensive Logging**: Detailed logging for troubleshooting and auditing.

## Scalability Considerations

1. **Lambda Auto-scaling**: Functions will automatically scale with load.

2. **API Gateway Throttling**: Controlling request rates to prevent overloading.

3. **Slack Rate Limits**: Managing message delivery to respect Slack API limits. 