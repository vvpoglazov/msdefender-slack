# Microsoft Defender Vulnerability Notification System

A serverless solution that forwards Microsoft Defender vulnerability information to Slack and provides daily summary reports of high and critical severity vulnerabilities.

## Overview

This system integrates Microsoft Defender vulnerability data with Slack using AWS serverless technologies. It provides:

1.  **Real-time Notifications**: Forwards vulnerability information matching configured severity levels (default: high, critical) to a designated Slack channel.
2.  **Daily Summary Reports**: Generates daily reports summarizing vulnerabilities matching the severity filter at 9:00 AM UTC (configurable via EventBridge schedule in Terraform) on working days.
3.  **Monday Reports**: Includes the past 72 hours of vulnerabilities in Monday reports to cover weekend activity.
4.  **Weekday Reports**: Includes the past 24 hours of vulnerabilities for Tuesday through Friday.

## Architecture

The system uses AWS Lambda, API Gateway, EventBridge, and Secrets Manager to create a serverless event-driven architecture:

```
                                      ┌─────────────────┐
                                      │                 │
                                      │  AWS Secrets    │
                                      │    Manager      │
                                      │                 │
                                      └─────┬───────────┘
                                            │
                                            │ API Keys + Tenant ID
                                            │
┌─────────────────┐    ┌─────────────┐    ┌▼───────────────┐    ┌─────────────┐
│                 │    │             │    │                 │    │             │
│    Microsoft    │    │  AWS API    │    │  AWS Lambda     │    │  Slack      │
│    Defender     ├───►│  Gateway    ├───►│  (Vulnerability ├───►│  Channels   │
│                 │    │             │    │   Reporter)     │    │             │
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

## Setup and Deployment

### Prerequisites

*   AWS Account with appropriate permissions (IAM user/role for Terraform execution).
*   Python 3.9+ installed locally.
*   Terraform 1.0+ installed locally.
*   AWS CLI installed and configured with credentials (`aws configure`).
*   Access to Microsoft Azure portal to register an Azure AD application.
*   Access to a Slack workspace with permissions to create and install apps.

### Installation Steps

1.  **Clone Repository**: `git clone https://github.com/your-org/msdefender-slack.git` and `cd msdefender-slack`

2.  **Setup Python Environment**: Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Azure AD App Registration (for Defender API)**:
    *   Navigate to Azure Portal > Azure Active Directory > App registrations > + New registration.
    *   Give it a name (e.g., `DefenderSlackNotifier`). Select "Accounts in this organizational directory only".
    *   Register the application.
    *   Note the **Application (client) ID** and **Directory (tenant) ID**.
    *   Go to "Certificates & secrets" > "Client secrets" > + New client secret. Copy the generated secret **Value** immediately (this is your client secret).
    *   Go to "API permissions" > + Add a permission > APIs my organization uses > Search for and select "WindowsDefenderATP".
    *   Select "Application permissions". Add at least `Alert.Read.All`. Grant admin consent.

4.  **Slack App Setup**:
    *   Go to [https://api.slack.com/apps](https://api.slack.com/apps) and click "Create New App" > "From scratch".
    *   Give your app a name and select your workspace.
    *   Navigate to "OAuth & Permissions" in the sidebar.
    *   Under "Scopes" > "Bot Token Scopes", add `chat:write` (to post messages) and `files:write` (if you plan to use file uploads, currently not implemented but good practice).
    *   Click "Install to Workspace" at the top and authorize the app.
    *   Copy the **Bot User OAuth Token** (starts with `xoxb-`).
    *   Add the bot to the channel where you want alerts and summaries to be posted.

5.  **Configure Secrets in AWS Secrets Manager**:
    *   **Manually:** Navigate to AWS Secrets Manager in the AWS Console. Find or create a secret (default name expected by Terraform is `<project_name>-api-keys`, e.g., `msdefender-slack-api-keys`). Store the secrets as a JSON object:
        ```json
        {
          "microsoft_defender_client_id": "YOUR_AZURE_APP_CLIENT_ID",
          "microsoft_defender_client_secret": "YOUR_AZURE_APP_CLIENT_SECRET",
          "microsoft_defender_tenant_id": "YOUR_AZURE_DIRECTORY_TENANT_ID",
          "slack_api_token": "YOUR_SLACK_BOT_TOKEN_xoxb-..."
        }
        ```
    *   **Via Terraform (Recommended):** Update the `infra/variables.tf` or create a `terraform.tfvars` file with these values, and let Terraform manage the secret creation (ensure the Terraform configuration supports this).

6.  **Deploy Infrastructure with Terraform**:
    *   Navigate to the `infra/` directory.
    *   Initialize Terraform: `terraform init`
    *   Review the plan: `terraform plan`
    *   Apply the configuration: `terraform apply` (confirm with `yes`)
    *   Note the outputs, especially the `api_gateway_invoke_url`.

7.  **Configure Defender Webhook**: (This step might vary depending on Defender portal changes)
    *   Navigate to your Microsoft Defender portal (e.g., security.microsoft.com).
    *   Find settings related to API connections, SIEM integration, or Streaming API.
    *   Configure a webhook or streaming API rule to send alert notifications to the `api_gateway_invoke_url` obtained from the Terraform output.
    *   Refer to the [Microsoft Defender for Endpoint documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/streaming-api) for detailed instructions on setting up streaming alerts.

8.  **Configure Lambda Environment Variables (via Terraform)**:
    *   The Terraform configuration (`infra/main.tf` or similar) should set the following environment variables for both Lambda functions (`alert_processor` and `summary_generator`):
        *   `SLACK_CHANNEL`: The target Slack channel name (e.g., `security-alerts`).
        *   `ALERT_SEVERITY_FILTER`: Comma-separated list of severities to process (e.g., `high,critical`).
        *   `LOG_LEVEL`: (Optional) Set log level, e.g., `DEBUG`, `INFO`, `WARNING` (defaults to `INFO`).
        *   `DEFENDER_ALERT_URL_BASE`: (Optional) Base URL for alert links in Slack.
        *   `DEFENDER_PORTAL_URL`: (Optional) URL for the "View All" button in summaries.
        *   (Other Defender URLs are configurable but have defaults).

## Testing

### Local Testing

Testing locally requires mocking AWS services (Secrets Manager) and external APIs (Defender, Slack) or providing real credentials via environment variables.

**Prerequisites for Local Testing:**

1.  **Set Environment Variables:** Export the required secrets and configuration as environment variables in your terminal session:
    ```bash
    export SLACK_API_TOKEN="YOUR_SLACK_BOT_TOKEN_xoxb-..."
    export DEFENDER_CLIENT_ID="YOUR_AZURE_APP_CLIENT_ID"
    export DEFENDER_CLIENT_SECRET="YOUR_AZURE_APP_CLIENT_SECRET"
    export DEFENDER_TENANT_ID="YOUR_AZURE_DIRECTORY_TENANT_ID"
    export SLACK_CHANNEL="your-test-slack-channel"
    export ALERT_SEVERITY_FILTER="high,critical"
    export AWS_REGION="your-aws-region" # e.g., us-east-1
    # Optional: Set if you want to override defaults
    # export LOG_LEVEL="DEBUG"
    # export DEFENDER_ALERT_URL_BASE="..."
    # export DEFENDER_PORTAL_URL="..."
    # Tell secret_manager.py to use environment variables
    export ENVIRONMENT="dev" 
    ```

2.  **AWS Credentials:** Ensure your AWS CLI is configured (`aws configure`) or appropriate AWS environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) are set if your code needs to interact with AWS services directly during tests (though `secret_manager.py` has a fallback for `ENVIRONMENT=dev`).

### Running Tests

*   **Unit Tests (Recommended):** Run unit tests using `pytest` and `unittest.mock` to test individual functions and classes in isolation:
    ```bash
    pytest tests/
    ```

*   **Run specific test files:**
    ```bash
    pytest tests/test_alert_processor.py
    pytest tests/test_summary_generator.py
    ```

*   **Testing with Coverage:**
    ```bash
    pytest --cov=src tests/
    ```

*   **Testing Handlers with Sample Events:** You can invoke the handlers directly with test events:

    *   **Alert Processor:**
        ```bash
        python tests/run_tests.py alert
        ```

    *   **Summary Generator:**
        ```bash
        python tests/run_tests.py summary
        ```

    *   The test events are stored in the `tests/events/` directory.

*   **Using AWS SAM CLI (Advanced):** For a more accurate local Lambda environment:
    ```bash
    # Install SAM CLI first
    sam local invoke AlertProcessor --event tests/events/alert_event.json --env-vars env.json
    sam local invoke SummaryGenerator --event tests/events/schedule_event.json --env-vars env.json
    ```

## Development Guide

### Development Workflow

1. **Clone the repository** and set up your local environment as described in the Setup section
2. **Create a feature branch** for your changes
3. **Make your code changes** following the project's code style
4. **Run tests** to ensure your changes don't break existing functionality
5. **Commit your changes** with clear, descriptive commit messages
6. **Submit a pull request** for review

### Code Style and Standards

This project follows these coding standards:

- **Python**: PEP 8 style guide with a line length of 100 characters
- **Formatting**: Use Black for automatic code formatting
- **Linting**: Use Pylint to check code quality
- **Import Sorting**: Use isort to organize imports

You can run code quality checks with:

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
pylint src/ tests/
```

### Adding New Features

When adding new features:

1. Start by writing tests that define the expected behavior
2. Implement the feature code in the appropriate module
3. Ensure all tests pass before submitting

## Troubleshooting

### Common Issues

1. **Secrets Not Found**: 
   - Check if the AWS Secrets Manager secret exists with the correct name
   - Verify IAM permissions for the Lambda function to access Secrets Manager
   - In development mode, ensure environment variables are set correctly

2. **Lambda Function Timeouts**:
   - Check CloudWatch Logs for specific errors
   - Consider increasing the Lambda timeout in the Terraform configuration
   - Optimize code that may be causing delays (API calls, processing large datasets)

3. **API Gateway Errors**:
   - Verify the correct API Gateway endpoint is being used
   - Check API Gateway logs and CloudWatch for error messages
   - Test the API Gateway endpoint directly using tools like Postman or curl

4. **Slack Message Delivery Issues**:
   - Verify the Slack token is valid and has the correct permissions
   - Ensure the bot has been added to the target channel
   - Check for rate limiting issues in logs

### Debugging

1. **CloudWatch Logs**: All Lambda functions log to CloudWatch. Set `LOG_LEVEL=DEBUG` for detailed logging.

2. **Local Debugging**: 
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

3. **Viewing Lambda Logs in AWS Console**:
   - Navigate to AWS Lambda in the console
   - Select your function
   - Go to the "Monitor" tab
   - Click "View logs in CloudWatch"

## Project Structure

```
msdefender-slack/
├── infra/                # Terraform infrastructure code
│   ├── main.tf           # Main Terraform configuration
│   └── variables.tf      # Terraform variables
├── scripts/              # Utility scripts (if any)
├── src/                  # Source code
│   ├── functions/        # Lambda functions
│   │   ├── alert_processor.py    # Alert processor function
│   │   └── summary_generator.py  # Summary generator function
│   └── lib/              # Shared libraries
│       ├── alert_formatter.py    # Format alerts for Slack
│       ├── defender_client.py    # Microsoft Defender API client
│       ├── secret_manager.py     # AWS Secrets Manager client
│       ├── slack_client.py       # Slack API client
│       ├── summary_formatter.py  # Format summaries for Slack
│       └── utils.py            # Shared utility functions
├── tests/                # Test files
│   ├── events/           # Sample events for testing
│   ├── test_alert_processor.py   # Tests for alert processor
│   ├── test_summary_generator.py # Tests for summary generator
│   ├── conftest.py       # Pytest fixtures
│   └── run_tests.py      # Test runner script
├── .gitignore            # Git ignore file
├── LICENSE               # License file
├── README.md             # Project documentation
├── requirements.txt      # Python dependencies
└── setup.py              # Package setup file
```

## Maintenance and Operations

### Monitoring

- **CloudWatch Metrics**: Monitor Lambda invocations, errors, and durations
- **CloudWatch Alarms**: Set up alarms for error thresholds and function execution failures
- **CloudWatch Dashboard**: Create a dashboard to visualize system performance

### Updates and Versioning

- **Dependency Updates**: Regularly check for and apply security updates to dependencies
- **AWS Lambda Versions**: Use Lambda versioning for stable deployments
- **Terraform State**: Keep Terraform state secure and backed up

## Security Considerations

- **Secrets Management**: All credentials are stored securely in AWS Secrets Manager
- **Least Privilege**: Lambda IAM roles follow the principle of least privilege
- **Input Validation**: All input data is validated before processing
- **Logging**: Sensitive data is never logged to CloudWatch
- **API Gateway Security**: Consider implementing API keys or other authentication methods

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Run tests
5. Submit a pull request

Please ensure your code follows the project's coding standards and includes appropriate tests.

## License

[MIT](LICENSE)

## Contact

For questions or support, please contact the security team.