# Microsoft Defender Slack Notification System

A serverless solution that forwards Microsoft Defender security alerts to Slack and provides daily summary reports of high and critical severity threats.

## Overview

This system integrates Microsoft Defender security alerts with Slack using AWS serverless technologies. It provides:

1.  **Real-time Notifications**: Forwards alerts matching configured severity levels (default: high, critical) to a designated Slack channel.
2.  **Daily Summary Reports**: Generates daily reports summarizing alerts matching the severity filter at 9:00 AM UTC (configurable via EventBridge schedule in Terraform) on working days.
3.  **Monday Reports**: Includes the past 72 hours of threats in Monday reports to cover weekend activity.
4.  **Weekday Reports**: Includes the past 24 hours of threats for Tuesday through Friday.

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

8.  **Configure Lambda Environment Variables (via Terraform)**:
    *   The Terraform configuration (`infra/main.tf` or similar) should set the following environment variables for both Lambda functions (`alert_processor` and `summary_generator`):
        *   `SLACK_CHANNEL`: The target Slack channel name (e.g., `security-alerts`).
        *   `ALERT_SEVERITY_FILTER`: Comma-separated list of severities to process (e.g., `high,critical`).
        *   `LOG_LEVEL`: (Optional) Set log level, e.g., `DEBUG`, `INFO`, `WARNING` (defaults to `INFO`).
        *   `DEFENDER_ALERT_URL_BASE`: (Optional) Base URL for alert links in Slack.
        *   `DEFENDER_PORTAL_URL`: (Optional) URL for the "View All" button in summaries.
        *   (Other Defender URLs are configurable but have defaults).

## Local Testing

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

**Running Tests:**

*   **Unit Tests (Recommended):** Implement unit tests using `pytest` and `unittest.mock` to test individual functions and classes in isolation. Mock external dependencies like `requests`, `slack_sdk`, `boto3`, and the helper libraries (`secret_manager`, formatters, clients).
    ```bash
    # Example (assuming tests are in a 'tests/' directory)
    pytest tests/
    ```

*   **Testing Handlers with Sample Events:** You can invoke the handlers directly by crafting sample event payloads.

    *   **Alert Processor:**
        1.  Create a JSON file (e.g., `sample_alert_event.json`) mimicking an API Gateway event containing a Defender alert in the `body` field.
        2.  Create a small Python script to load the event, set environment variables (if not already exported), and call the handler:
            ```python
            # Example: test_alert_handler.py
            import json
            from src.functions.alert_processor import handler

            # Load sample event
            with open('sample_alert_event.json', 'r') as f:
                event = json.load(f)
            
            # Call handler (ensure environment variables are set)
            response = handler(event, None) 
            print(response)
            ```
        3.  Run the script: `python test_alert_handler.py`

    *   **Summary Generator:**
        1.  Create a JSON file (e.g., `sample_schedule_event.json`) mimicking an EventBridge scheduled event (often an empty dictionary `{}`).
        2.  Create a script similar to the alert processor test script, importing and calling `src.functions.summary_generator.handler`.
        3.  Run the script: `python test_summary_handler.py` (This will attempt to connect to the real Defender API using the credentials in your environment variables).

*   **Using AWS SAM CLI (Advanced):** `sam local invoke` can simulate the Lambda environment more closely, allowing you to pass events and environment variable files. Refer to AWS SAM documentation.

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
├── .gitignore
├── LICENSE
├── README.md             # Project documentation
├── requirements.txt      # Python dependencies
```

## License

[MIT](LICENSE)