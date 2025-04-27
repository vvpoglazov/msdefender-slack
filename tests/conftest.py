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
    """Return a mock DefenderClient that returns sample vulnerabilities."""
    mock_client = MagicMock()
    mock_client.get_vulnerabilities.return_value = [
        {
            'id': 'CVE-2023-12345',
            'name': 'Test Critical Vulnerability',
            'severity': 'Critical',
            'description': 'This is a test critical severity vulnerability',
            'cvssV3': 9.8,
            'exposedMachines': 5,
            'publishedOn': '2023-06-15T10:00:00Z',
            'updatedOn': '2023-06-16T14:30:00Z',
            'publicExploit': True
        },
        {
            'id': 'CVE-2023-23456',
            'name': 'Test High Vulnerability',
            'severity': 'High',
            'description': 'This is a test high severity vulnerability',
            'cvssV3': 7.5,
            'exposedMachines': 3,
            'publishedOn': '2023-06-14T09:00:00Z',
            'updatedOn': '2023-06-15T11:20:00Z',
            'publicExploit': False
        },
        {
            'id': 'CVE-2023-34567',
            'name': 'Test Medium Vulnerability',
            'severity': 'Medium',
            'description': 'This is a test medium severity vulnerability',
            'cvssV3': 5.0,
            'exposedMachines': 2,
            'publishedOn': '2023-06-13T08:00:00Z',
            'updatedOn': '2023-06-13T16:45:00Z',
            'publicExploit': False
        }
    ]
    return mock_client


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
def mock_format_vulnerability():
    """Mock the format_vulnerability function to return test blocks."""
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Microsoft Defender Vulnerability: HIGH",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Test Vulnerability*\nThis is a test vulnerability."
            }
        }
    ]


@pytest.fixture
def mock_format_vulnerabilities_summary():
    """Mock the format_vulnerabilities_summary function to return test blocks."""
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Microsoft Defender Vulnerability Summary",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Found 2 High/Critical Vulnerabilities in the Last 24 Hours*"
            }
        }
    ] 