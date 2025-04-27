"""Tests for summary_generator.py Lambda function."""

import json
import os
import datetime
import pytest
from unittest.mock import patch, MagicMock

# Import the handler and other components from the function
from src.functions.summary_generator import handler, SummaryGenerator, Config


@pytest.fixture
def summary_generator_with_mocks(mock_secrets, mock_slack_client, mock_defender_client):
    """Return a SummaryGenerator instance with mocked dependencies."""
    with patch('src.functions.summary_generator.get_secrets', return_value=mock_secrets):
        generator = SummaryGenerator()
        generator.slack_client = mock_slack_client
        generator.defender_client = mock_defender_client
        generator.defender_tenant_id = mock_secrets['microsoft_defender_tenant_id']
        generator.initialized = True
        yield generator


@pytest.mark.parametrize("env_vars", [
    {},  # Test with no environment variables (use defaults)
    {"SLACK_CHANNEL": "custom-channel"},  # Test with custom channel
    {"VULNERABILITY_SEVERITY_FILTER": "high,critical,medium"},  # Test with custom severity filter
    {"SLACK_CHANNEL": "custom-channel", "VULNERABILITY_SEVERITY_FILTER": "critical"}  # Test with both custom values
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
        if "VULNERABILITY_SEVERITY_FILTER" in env_vars:
            expected_filter = [s.strip() for s in env_vars["VULNERABILITY_SEVERITY_FILTER"].split(",")]
            assert Config.get_severity_filter() == expected_filter
        else:
            assert Config.get_severity_filter() == Config.DEFAULT_SEVERITY_FILTER
    
    finally:
        # Clean up environment variables
        for key in env_vars:
            if key in os.environ:
                del os.environ[key]


@patch('src.functions.summary_generator.get_secrets')
def test_initialization(mock_get_secrets, mock_secrets):
    """Test the initialization process of SummaryGenerator."""
    mock_get_secrets.return_value = mock_secrets
    
    generator = SummaryGenerator()
    generator.initialize()
    
    assert generator.initialized is True
    assert generator.secrets == mock_secrets
    assert generator.defender_tenant_id == mock_secrets['microsoft_defender_tenant_id']
    
    # Initialize again to test it doesn't reinitialize
    original_secrets = generator.secrets
    generator.initialize()
    assert generator.secrets is original_secrets  # Should be the same object (not reinitialized)


@pytest.mark.parametrize("day_name,expected_type", [
    ("Monday", "Weekend"),
    ("Tuesday", "Daily"),
    ("Wednesday", "Daily"),
    ("Thursday", "Daily"),
    ("Friday", "Daily"),
    ("Saturday", "Daily"),
    ("Sunday", "Daily")
])
def test_determine_day_type(summary_generator_with_mocks, day_name, expected_type):
    """Test day type determination logic."""
    generator = summary_generator_with_mocks
    
    # Mock datetime to return a specific day
    with patch('src.functions.summary_generator.datetime') as mock_datetime:
        # Configure mock datetime.utcnow() to return a date with the specified day
        mock_date = MagicMock()
        mock_date.strftime.return_value = day_name
        mock_datetime.datetime.utcnow.return_value = mock_date
        
        # Test the function
        assert generator.determine_day_type() == expected_type


@pytest.mark.parametrize("day_type,expected_hours", [
    ("Weekend", 72),
    ("Daily", 24)
])
def test_determine_time_range(summary_generator_with_mocks, day_type, expected_hours):
    """Test time range determination logic."""
    generator = summary_generator_with_mocks
    
    # Mock determine_day_type to return the specified day type
    with patch.object(generator, 'determine_day_type', return_value=day_type):
        assert generator.determine_time_range() == expected_hours


def test_fetch_vulnerabilities_success(summary_generator_with_mocks):
    """Test successful vulnerability fetching."""
    generator = summary_generator_with_mocks
    
    # Call the function
    results = generator.fetch_vulnerabilities(24)
    
    # Verify results
    assert results is not None
    assert len(results) == 3  # Mock returns 3 vulnerabilities
    
    # Verify the defender client was called with correct parameters
    generator.defender_client.get_vulnerabilities.assert_called_once()
    call_args = generator.defender_client.get_vulnerabilities.call_args[1]
    assert call_args['hours_lookback'] == 24
    assert call_args['severity_filter'] is not None


def test_fetch_vulnerabilities_no_client(summary_generator_with_mocks):
    """Test vulnerability fetching with no initialized defender client."""
    generator = summary_generator_with_mocks
    generator.defender_client = None
    
    # Call the function
    results = generator.fetch_vulnerabilities(24)
    
    # Verify results
    assert results is None


@patch('src.functions.summary_generator.format_vulnerabilities_summary')
def test_generate_summary_with_vulnerabilities(mock_format_summary, summary_generator_with_mocks):
    """Test generating summary when vulnerabilities are found."""
    generator = summary_generator_with_mocks
    
    # Use fixture blocks for the mock return value
    mock_format_summary.return_value = [
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
                "text": "*Found 2 High/Critical Vulnerabilities*"
            }
        }
    ]
    
    # Configure generator mock to return vulnerabilities
    with patch.object(generator, 'fetch_vulnerabilities') as mock_fetch:
        mock_fetch.return_value = [
            {"id": "CVE-2023-12345", "severity": "Critical", "name": "Test Vulnerability 1"},
            {"id": "CVE-2023-23456", "severity": "High", "name": "Test Vulnerability 2"}
        ]
        
        # Call generate_summary
        result = generator.generate_summary("test-channel", ["Critical", "High"])
        
        # Verify the result
        assert result["statusCode"] == 200
        assert "Vulnerabilities reported successfully" in json.loads(result["body"])["message"]
        
        # Verify the mocks were called correctly
        mock_fetch.assert_called_once()
        mock_format_summary.assert_called_once()
        generator.slack_client.post_message.assert_called_once()


def test_filter_vulnerabilities_by_severity(summary_generator_with_mocks):
    """Test filtering vulnerabilities by severity."""
    generator = summary_generator_with_mocks
    
    # Test data
    vulnerabilities = [
        {'id': '1', 'severity': 'high'},
        {'id': '2', 'severity': 'medium'},
        {'id': '3', 'severity': 'low'},
        {'id': '4', 'severity': 'critical'},
        {'id': '5', 'severity': 'HIGH'},  # Test case insensitivity
        {'id': '6'}  # Missing severity
    ]
    
    # Test with different severity filters
    high_critical_filter = ['high', 'critical']
    filtered = generator.filter_vulnerabilities_by_severity(vulnerabilities, high_critical_filter)
    assert len(filtered) == 3
    assert all(vulnerability['id'] in ['1', '4', '5'] for vulnerability in filtered)
    
    # Test with empty vulnerabilities list
    assert generator.filter_vulnerabilities_by_severity([], high_critical_filter) == []
    
    # Test with different filter
    medium_filter = ['medium']
    filtered = generator.filter_vulnerabilities_by_severity(vulnerabilities, medium_filter)
    assert len(filtered) == 1
    assert filtered[0]['id'] == '2'


@patch('src.functions.summary_generator.format_vulnerabilities_summary')
def test_generate_summary_no_matching_vulnerabilities(mock_format_summary, summary_generator_with_mocks):
    """Test generating summary when no vulnerabilities match severity filter."""
    generator = summary_generator_with_mocks
    
    # Configure mock to return vulnerabilities that don't match filter
    generator.defender_client.get_vulnerabilities.return_value = [
        {'id': '1', 'severity': 'medium'},
        {'id': '2', 'severity': 'low'}
    ]
    
    # Mock the time range function
    with patch.object(generator, 'determine_time_range', return_value=24):
        # Call the function
        result = generator.generate_summary('test-channel', ['high', 'critical'])
        
        # Verify results
        assert result['statusCode'] == 200
        assert 'No matching vulnerabilities to report' in json.loads(result['body'])['message']
        
        # Verify format_vulnerabilities_summary was not called (no vulnerabilities to format)
        mock_format_summary.assert_not_called()


def test_generate_summary_no_vulnerabilities_returned(summary_generator_with_mocks):
    """Test generating summary when no vulnerabilities are found at all."""
    generator = summary_generator_with_mocks
    
    # Configure mock to return empty list
    generator.defender_client.get_vulnerabilities.return_value = []
    
    # Mock the time range function
    with patch.object(generator, 'determine_time_range', return_value=24):
        # Call the function
        result = generator.generate_summary('test-channel', ['high', 'critical'])
        
        # Verify results
        assert result['statusCode'] == 200
        assert 'No matching vulnerabilities to report' in json.loads(result['body'])['message']


def test_generate_summary_fetch_error(summary_generator_with_mocks):
    """Test generating summary when fetch fails."""
    generator = summary_generator_with_mocks
    
    # Configure mock to return None (simulating fetch failure)
    with patch.object(generator, 'fetch_vulnerabilities', return_value=None):
        # Mock the send_error_notification method
        with patch.object(generator, 'send_error_notification') as mock_send_error:
            # Call the function
            result = generator.generate_summary('test-channel', ['high', 'critical'])
            
            # Verify results
            assert result['statusCode'] == 500
            assert 'Failed to fetch vulnerabilities' in json.loads(result['body'])['message']
            
            # Verify error notification was sent
            mock_send_error.assert_called_once()


def test_send_no_vulnerabilities_message_success(summary_generator_with_mocks):
    """Test sending 'no vulnerabilities' message successfully."""
    generator = summary_generator_with_mocks
    
    # Call the function
    result = generator.send_no_vulnerabilities_message('test-channel', 24, 'high,critical')
    
    # Verify results
    assert result['statusCode'] == 200
    assert 'No matching vulnerabilities to report' in json.loads(result['body'])['message']
    
    # Verify the Slack client was called
    generator.slack_client.post_message.assert_called_once()
    # Extract and verify the first block's text
    call_args = generator.slack_client.post_message.call_args[1]
    blocks = call_args.get('blocks')
    assert blocks[1]['text']['text'].startswith('*No vulnerabilities matching severity levels')


def test_send_no_vulnerabilities_message_error(summary_generator_with_mocks):
    """Test handling errors when sending 'no vulnerabilities' message."""
    generator = summary_generator_with_mocks
    
    # Configure mock to return error
    generator.slack_client.post_message.return_value = {'ok': False, 'error': 'channel_not_found'}
    
    # Call the function
    result = generator.send_no_vulnerabilities_message('invalid-channel', 24, 'high,critical')
    
    # Verify results
    assert result['statusCode'] == 500
    assert 'Failed to send' in json.loads(result['body'])['message']


def test_send_error_notification(summary_generator_with_mocks):
    """Test sending error notifications."""
    generator = summary_generator_with_mocks
    
    # Call the function
    generator.send_error_notification('test-channel', 'Test error message')
    
    # Verify the Slack client was called
    generator.slack_client.post_message.assert_called_once()
    
    # Extract and verify parameters
    call_args = generator.slack_client.post_message.call_args[1]
    assert call_args.get('channel') == 'test-channel'
    assert call_args.get('text') == 'Error: Test error message'
    blocks = call_args.get('blocks')
    assert 'Test error message' in blocks[0]['text']['text']


def test_send_error_notification_no_client(summary_generator_with_mocks):
    """Test sending error notification with no Slack client."""
    generator = summary_generator_with_mocks
    generator.slack_client = None
    
    # This shouldn't raise an exception
    generator.send_error_notification('test-channel', 'Test error message')


@patch('src.functions.summary_generator.SummaryGenerator')
@patch('src.functions.summary_generator.Config')
def test_handler_success(mock_config, mock_summary_generator_class, summary_generator_with_mocks, eventbridge_event):
    """Test successful execution of the Lambda handler."""
    # Set up mocks
    mock_config.get_slack_channel.return_value = 'test-channel'
    mock_config.get_severity_filter.return_value = ['high', 'critical']

    # Create a mock of the generator that will be returned by SummaryGenerator()
    mock_generator_instance = MagicMock()
    mock_generator_instance.generate_summary.return_value = {
        'statusCode': 200,
        'body': json.dumps({'message': 'Summary report sent successfully'})
    }
    mock_generator_instance.initialized = True
    mock_generator_instance.slack_client = MagicMock()
    mock_generator_instance.defender_client = MagicMock()
    
    # Make SummaryGenerator() return our mock
    mock_summary_generator_class.return_value = mock_generator_instance
    
    # Call the handler with a patched global generator instance
    with patch('src.functions.summary_generator.generator', mock_generator_instance):
        result = handler(eventbridge_event, {})
    
    # Verify results
    assert result['statusCode'] == 200
    assert json.loads(result['body'])['message'] == 'Summary report sent successfully'
    mock_generator_instance.initialize.assert_called_once()
    mock_generator_instance.generate_summary.assert_called_once()
    
    # Verify the correct arguments were passed to generate_summary
    generate_summary_args = mock_generator_instance.generate_summary.call_args[0]
    assert generate_summary_args[0] == mock_config.get_slack_channel.return_value  # channel
    assert generate_summary_args[1] == mock_config.get_severity_filter.return_value  # severity_filter


@patch('src.functions.summary_generator.SummaryGenerator')
@patch('src.functions.summary_generator.Config')
def test_handler_no_slack_client(mock_config, mock_summary_generator_class, eventbridge_event):
    """Test handler behavior when Slack client is not available."""
    # Create a mock of the generator that will be returned by SummaryGenerator()
    mock_generator_instance = MagicMock()
    mock_generator_instance.initialize.return_value = None
    mock_generator_instance.slack_client = None  # No Slack client
    mock_generator_instance.defender_client = MagicMock()  # But we have Defender client
    mock_generator_instance.initialized = True
    
    # Make SummaryGenerator() return our mock
    mock_summary_generator_class.return_value = mock_generator_instance
    
    # Call the handler with a patched global generator instance
    with patch('src.functions.summary_generator.generator', mock_generator_instance):
        result = handler(eventbridge_event, {})
    
    # Verify results
    assert result['statusCode'] == 500
    assert 'Slack client could not be initialized' in json.loads(result['body'])['message']
    mock_generator_instance.initialize.assert_called_once()
    mock_generator_instance.generate_summary.assert_not_called()


@patch('src.functions.summary_generator.SummaryGenerator')
@patch('src.functions.summary_generator.Config')
def test_handler_no_defender_client(mock_config, mock_summary_generator_class, eventbridge_event):
    """Test handler behavior when Defender client is not available."""
    # Create a mock of the generator that will be returned by SummaryGenerator()
    mock_generator_instance = MagicMock()
    mock_generator_instance.initialize.return_value = None
    mock_generator_instance.slack_client = MagicMock()  # We have Slack client
    mock_generator_instance.defender_client = None  # But no Defender client
    mock_generator_instance.initialized = True
    
    # Make SummaryGenerator() return our mock
    mock_summary_generator_class.return_value = mock_generator_instance
    
    # Call the handler with a patched global generator instance
    with patch('src.functions.summary_generator.generator', mock_generator_instance):
        result = handler(eventbridge_event, {})
    
    # Verify results
    assert result['statusCode'] == 500
    assert 'Defender client could not be initialized' in json.loads(result['body'])['message']
    mock_generator_instance.initialize.assert_called_once()
    mock_generator_instance.generate_summary.assert_not_called()


@patch('src.functions.summary_generator.SummaryGenerator')
@patch('src.functions.summary_generator.Config')
def test_handler_exception(mock_config, mock_summary_generator_class, eventbridge_event):
    """Test handler behavior when an exception occurs."""
    # Create a mock of the generator that will be returned by SummaryGenerator()
    mock_generator_instance = MagicMock()
    # Simulate an exception during initialize
    mock_generator_instance.initialize.side_effect = Exception("Test exception")
    
    # Make SummaryGenerator() return our mock
    mock_summary_generator_class.return_value = mock_generator_instance
    
    # Call the handler with a patched global generator instance
    with patch('src.functions.summary_generator.generator', mock_generator_instance):
        result = handler(eventbridge_event, {})
    
    # Verify results
    assert result['statusCode'] == 500
    assert 'Internal server error' in json.loads(result['body'])['message']
    mock_generator_instance.initialize.assert_called_once()
    mock_generator_instance.generate_summary.assert_not_called() 