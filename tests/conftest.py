"""Common test fixtures and utilities for Lambda function tests."""

import json
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_secrets():
    """Mock secrets for testing."""
    return {
        'slack_api_token': 'xoxb-mock-slack-token',
        'microsoft_defender_tenant_id': 'mock-tenant-id',
        'microsoft_defender_client_id': 'mock-client-id',
        'microsoft_defender_client_secret': 'mock-client-secret'
    }


@pytest.fixture
def mock_slack_client():
    """Return a mock SlackClient that returns success responses."""
    mock_client = MagicMock()
    mock_client.post_message.return_value = {'ok': True, 'channel': 'test-channel', 'ts': '1234567890.123456'}
    return mock_client


@pytest.fixture
def mock_defender_client():
    """Return a mock DefenderClient that returns sample alerts."""
    mock_client = MagicMock()
    mock_client.get_alerts.return_value = [
        {
            'id': 'alert-id-1',
            'title': 'Test Security Alert 1',
            'alertSeverity': 'high',
            'description': 'This is a test high severity alert',
            'createdDateTime': '2023-06-15T10:00:00Z',
            'status': 'new'
        },
        {
            'id': 'alert-id-2',
            'title': 'Test Security Alert 2',
            'alertSeverity': 'medium',
            'description': 'This is a test medium severity alert',
            'createdDateTime': '2023-06-15T11:00:00Z',
            'status': 'new'
        },
        {
            'id': 'alert-id-3',
            'title': 'Test Security Alert 3',
            'alertSeverity': 'critical',
            'description': 'This is a test critical severity alert',
            'createdDateTime': '2023-06-15T12:00:00Z',
            'status': 'new'
        }
    ]
    return mock_client


@pytest.fixture
def api_gateway_event():
    """Return a mock API Gateway event with a Defender alert payload."""
    return {
        'body': json.dumps({
            'id': 'alert-id-1',
            'title': 'Test Security Alert',
            'alertSeverity': 'high',
            'description': 'This is a test alert from Defender',
            'createdDateTime': '2023-06-15T10:00:00Z',
            'status': 'new',
            'category': 'InitialAccess',
            'sourceMaterials': ['https://example.com/alert/1'],
            'vendorInformation': {
                'provider': 'Microsoft',
                'providerVersion': '1.0'
            }
        }),
        'requestContext': {
            'identity': {
                'sourceIp': '192.168.1.1'
            },
            'requestId': 'test-request-id'
        },
        'headers': {
            'Content-Type': 'application/json'
        }
    }


@pytest.fixture
def eventbridge_event():
    """Return a mock EventBridge scheduled event."""
    return {
        'version': '0',
        'id': 'scheduled-event-id',
        'detail-type': 'Scheduled Event',
        'source': 'aws.events',
        'account': '123456789012',
        'time': '2023-06-15T08:00:00Z',
        'region': 'us-east-1',
        'resources': [
            'arn:aws:events:us-east-1:123456789012:rule/daily-summary'
        ],
        'detail': {}
    }


@pytest.fixture
def mock_format_alert():
    """Mock the format_alert function to return test blocks."""
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Microsoft Defender Security Alert: High Severity",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Test Security Alert*"
            }
        }
    ]


@pytest.fixture
def mock_format_summary():
    """Mock the format_summary function to return test blocks."""
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Microsoft Defender Daily Security Summary",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*2 High/Critical Alerts in the Last 24 Hours*"
            }
        }
    ] 