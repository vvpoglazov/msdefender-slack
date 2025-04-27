"""Tests for alert_processor.py Lambda function."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Import the handler and other components from the function
from src.functions.alert_processor import handler, AlertProcessor, Config


@pytest.fixture
def alert_processor_with_mocks(mock_secrets, mock_slack_client):
    """Return an AlertProcessor instance with mocked dependencies."""
    with patch('src.functions.alert_processor.get_secrets', return_value=mock_secrets):
        processor = AlertProcessor()
        processor.slack_client = mock_slack_client
        processor.initialized = True
        yield processor


@pytest.mark.parametrize("env_vars", [
    {},  # Test with no environment variables (use defaults)
    {"SLACK_CHANNEL": "custom-channel"},  # Test with custom channel
    {"ALERT_SEVERITY_FILTER": "high,critical,medium"},  # Test with custom severity filter
    {"SLACK_CHANNEL": "custom-channel", "ALERT_SEVERITY_FILTER": "critical"}  # Test with both custom values
])
def test_config_values(env_vars):
    """Test that Config correctly reads environment variables with different settings."""
    # Set environment variables for the test
    for key, value in env_vars.items():
        os.environ[key] = value
    
    # Clean up after test
    try:
        # Test slack channel
        if "SLACK_CHANNEL" in env_vars:
            assert Config.get_slack_channel() == env_vars["SLACK_CHANNEL"]
        else:
            assert Config.get_slack_channel() == Config.DEFAULT_SLACK_CHANNEL
        
        # Test severity filter
        if "ALERT_SEVERITY_FILTER" in env_vars:
            expected_filter = [s.strip() for s in env_vars["ALERT_SEVERITY_FILTER"].split(",")]
            assert Config.get_severity_filter() == expected_filter
        else:
            assert Config.get_severity_filter() == Config.DEFAULT_SEVERITY_FILTER
    
    finally:
        # Clean up environment variables
        for key in env_vars:
            if key in os.environ:
                del os.environ[key]


@patch('src.functions.alert_processor.get_secrets')
def test_initialization(mock_get_secrets, mock_secrets):
    """Test the initialization process of AlertProcessor."""
    mock_get_secrets.return_value = mock_secrets
    
    processor = AlertProcessor()
    processor.initialize()
    
    assert processor.initialized is True
    assert processor.secrets == mock_secrets
    assert processor.defender_tenant_id == mock_secrets['microsoft_defender_tenant_id']
    
    # Initialize again to test it doesn't reinitialize
    original_secrets = processor.secrets
    processor.initialize()
    assert processor.secrets is original_secrets  # Should be the same object (not reinitialized)


def test_validate_alert(alert_processor_with_mocks):
    """Test alert validation logic."""
    processor = alert_processor_with_mocks
    
    # Valid alert should pass validation
    valid_alert = {
        'id': 'alert-id',
        'alertSeverity': 'high',
        'title': 'Test Alert'
    }
    assert processor.validate_alert(valid_alert) is True
    
    # Missing required fields should fail validation
    invalid_alerts = [
        {'id': 'alert-id', 'alertSeverity': 'high'},  # Missing title
        {'id': 'alert-id', 'title': 'Test Alert'},    # Missing alertSeverity
        {'alertSeverity': 'high', 'title': 'Test Alert'},  # Missing id
        {}  # Empty alert
    ]
    
    for invalid_alert in invalid_alerts:
        assert processor.validate_alert(invalid_alert) is False


def test_should_process_alert(alert_processor_with_mocks):
    """Test severity filtering logic."""
    processor = alert_processor_with_mocks
    
    # Test with different severity filters
    severity_filter = ['high', 'critical']
    
    # Alerts that match the filter should be processed
    alerts_to_process = [
        {'id': 'alert-1', 'alertSeverity': 'high'},
        {'id': 'alert-2', 'alertSeverity': 'critical'},
        {'id': 'alert-3', 'alertSeverity': 'HIGH'},  # Case insensitive
        {'id': 'alert-4', 'alertSeverity': 'CRITICAL'}  # Case insensitive
    ]
    
    for alert in alerts_to_process:
        assert processor.should_process_alert(alert, severity_filter) is True
    
    # Alerts that don't match the filter should not be processed
    alerts_to_skip = [
        {'id': 'alert-5', 'alertSeverity': 'medium'},
        {'id': 'alert-6', 'alertSeverity': 'low'},
        {'id': 'alert-7', 'alertSeverity': ''},  # Empty severity
        {'id': 'alert-8'}  # No severity
    ]
    
    for alert in alerts_to_skip:
        assert processor.should_process_alert(alert, severity_filter) is False
    
    # None should not be processed
    assert processor.should_process_alert(None, severity_filter) is False


def test_parse_alert_valid(alert_processor_with_mocks, api_gateway_event):
    """Test parsing a valid alert from API Gateway event."""
    processor = alert_processor_with_mocks
    
    parsed_alert = processor.parse_alert(api_gateway_event)
    assert parsed_alert is not None
    assert parsed_alert['id'] == 'alert-id-1'
    assert parsed_alert['alertSeverity'] == 'high'


def test_parse_alert_invalid(alert_processor_with_mocks):
    """Test parsing an invalid alert from API Gateway event."""
    processor = alert_processor_with_mocks
    
    # Test with missing body
    assert processor.parse_alert({}) is None
    
    # Test with invalid JSON
    assert processor.parse_alert({'body': '{"invalid json'}) is None
    
    # Test with non-dict JSON
    assert processor.parse_alert({'body': '"string_value"'}) is None
    
    # Test with missing required fields
    assert processor.parse_alert({'body': json.dumps({'id': 'test'})}) is None


@patch('src.functions.alert_processor.format_alert')
def test_process_alert_match_severity(mock_format_alert, alert_processor_with_mocks):
    """Test processing an alert that matches severity filter."""
    processor = alert_processor_with_mocks
    # Use mock_format_alert fixture value for the return value
    mock_format_alert.return_value = [
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
    
    alert_data = {
        'id': 'alert-id-1',
        'title': 'Test Security Alert',
        'alertSeverity': 'high'
    }
    
    severity_filter = ['high', 'critical']
    slack_channel = 'test-channel'
    
    result = processor.process_alert(alert_data, severity_filter, slack_channel)
    
    assert result['statusCode'] == 200
    assert json.loads(result['body'])['message'] == 'Alert processed successfully'
    mock_format_alert.assert_called_once_with(alert_data)
    processor.slack_client.post_message.assert_called_once()


@patch('src.functions.alert_processor.format_alert')
def test_process_alert_no_match_severity(mock_format_alert, alert_processor_with_mocks):
    """Test processing an alert that doesn't match severity filter."""
    processor = alert_processor_with_mocks
    
    alert_data = {
        'id': 'alert-id-2',
        'title': 'Test Security Alert',
        'alertSeverity': 'medium'
    }
    
    severity_filter = ['high', 'critical']
    slack_channel = 'test-channel'
    
    result = processor.process_alert(alert_data, severity_filter, slack_channel)
    
    assert result['statusCode'] == 200
    assert 'skipped' in json.loads(result['body'])['message']
    mock_format_alert.assert_not_called()
    processor.slack_client.post_message.assert_not_called()


@patch('src.functions.alert_processor.format_alert')
def test_process_alert_slack_error(mock_format_alert, alert_processor_with_mocks):
    """Test handling Slack API error during alert processing."""
    processor = alert_processor_with_mocks
    # Use mock_format_alert fixture value for the return value
    mock_format_alert.return_value = [
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
    
    # Configure mock to return error
    processor.slack_client.post_message.return_value = {'ok': False, 'error': 'channel_not_found'}
    
    alert_data = {
        'id': 'alert-id-1',
        'title': 'Test Security Alert',
        'alertSeverity': 'high'
    }
    
    severity_filter = ['high', 'critical']
    slack_channel = 'invalid-channel'
    
    result = processor.process_alert(alert_data, severity_filter, slack_channel)
    
    assert result['statusCode'] == 500
    assert 'Failed to send alert to Slack' in json.loads(result['body'])['message']


@patch('src.functions.alert_processor.AlertProcessor')
@patch('src.functions.alert_processor.Config')
def test_handler_success(mock_config, mock_alert_processor_class, alert_processor_with_mocks, api_gateway_event, mock_format_alert):
    """Test successful execution of the Lambda handler."""
    # Set up mocks
    mock_config.get_slack_channel.return_value = 'test-channel'
    mock_config.get_severity_filter.return_value = ['high', 'critical']

    # Create a mock of the processor that will be returned by AlertProcessor()
    mock_processor_instance = MagicMock()
    mock_processor_instance.parse_alert.return_value = json.loads(api_gateway_event['body'])
    mock_processor_instance.process_alert.return_value = {
        'statusCode': 200,
        'body': json.dumps({'message': 'Alert processed successfully'})
    }
    mock_processor_instance.initialized = True
    mock_processor_instance.slack_client = MagicMock()
    
    # Make AlertProcessor() return our mock
    mock_alert_processor_class.return_value = mock_processor_instance
    
    # Call the handler with a patched global processor instance
    with patch('src.functions.alert_processor.processor', mock_processor_instance):
        result = handler(api_gateway_event, {})
    
    # Verify results
    assert result['statusCode'] == 200
    mock_processor_instance.initialize.assert_called_once()
    mock_processor_instance.parse_alert.assert_called_once_with(api_gateway_event)
    mock_processor_instance.process_alert.assert_called_once()
    
    # Verify the correct arguments were passed to process_alert
    process_alert_args = mock_processor_instance.process_alert.call_args[0]
    assert process_alert_args[0] == json.loads(api_gateway_event['body'])  # alert_data
    assert process_alert_args[1] == ['high', 'critical']  # severity_filter
    assert process_alert_args[2] == 'test-channel'  # slack_channel


@patch('src.functions.alert_processor.AlertProcessor')
@patch('src.functions.alert_processor.Config')
def test_handler_invalid_payload(mock_config, mock_alert_processor_class, alert_processor_with_mocks):
    """Test handler behavior with invalid payload."""
    # Event with invalid body
    invalid_event = {'body': 'invalid json data'}
    
    # Create a mock of the processor that will be returned by AlertProcessor()
    mock_processor_instance = MagicMock()
    mock_processor_instance.parse_alert.return_value = None  # Simulate invalid payload
    mock_processor_instance.initialized = True
    mock_processor_instance.slack_client = MagicMock()
    
    # Make AlertProcessor() return our mock
    mock_alert_processor_class.return_value = mock_processor_instance
    
    # Call the handler with a patched global processor instance
    with patch('src.functions.alert_processor.processor', mock_processor_instance):
        result = handler(invalid_event, {})
    
    # Verify results for invalid payload
    assert result['statusCode'] == 400
    assert 'Invalid alert payload' in json.loads(result['body'])['message']
    mock_processor_instance.initialize.assert_called_once()
    mock_processor_instance.parse_alert.assert_called_once_with(invalid_event)
    mock_processor_instance.process_alert.assert_not_called()


@patch('src.functions.alert_processor.AlertProcessor')
@patch('src.functions.alert_processor.Config')
def test_handler_exception(mock_config, mock_alert_processor_class, alert_processor_with_mocks, api_gateway_event):
    """Test handler behavior when an exception occurs."""
    # Create a mock of the processor that will be returned by AlertProcessor()
    mock_processor_instance = MagicMock()
    # Simulate an exception during initialize
    mock_processor_instance.initialize.side_effect = Exception("Test exception")
    
    # Make AlertProcessor() return our mock
    mock_alert_processor_class.return_value = mock_processor_instance
    
    # Call the handler with a patched global processor instance
    with patch('src.functions.alert_processor.processor', mock_processor_instance):
        result = handler(api_gateway_event, {})
    
    # Verify results for exception
    assert result['statusCode'] == 500
    assert 'Internal server error' in json.loads(result['body'])['message']
    mock_processor_instance.initialize.assert_called_once()
    mock_processor_instance.parse_alert.assert_not_called()
    mock_processor_instance.process_alert.assert_not_called()


def test_handler_no_slack_client(alert_processor_with_mocks, api_gateway_event):
    """Test handler behavior when Slack client is not available."""
    with patch('src.functions.alert_processor.processor') as mock_processor:
        # Set up the mock processor
        mock_processor.initialize.return_value = None
        mock_processor.slack_client = None
        mock_processor.initialized = True
        
        # Call the handler
        result = handler(api_gateway_event, {})
        
        # Verify results
        assert result['statusCode'] == 500
        assert 'Slack client could not be initialized' in json.loads(result['body'])['message']
        mock_processor.initialize.assert_called_once()
        mock_processor.parse_alert.assert_not_called() 