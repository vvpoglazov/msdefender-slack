# Microsoft Defender Slack Notification - Testing

This directory contains tests for the Microsoft Defender Slack Notification system. The tests are designed to run with mocked clients, so you don't need real API keys for Microsoft Defender or Slack to run them.

## Running Tests Without API Keys

The test suite uses Python's `unittest.mock` library to mock external dependencies like Slack and Microsoft Defender APIs. This allows you to test the functionality without needing real API credentials.

### Prerequisites

Make sure you have the required packages installed:

```bash
pip install pytest pytest-mock
```

### Running Tests

You can run the tests using the provided script:

```bash
python tests/run_tests.py
```

Or directly with pytest:

```bash
pytest -xvs tests/
```

## Test Structure

The test suite includes:

1. **Unit Tests** - Testing individual functions in isolation with mocked dependencies
2. **Integration Tests** - Testing interactions between components with mocked external services
3. **Mock Fixtures** - Reusable mock objects and sample data

### Test Files

- `conftest.py` - Common fixtures and utilities for tests
- `test_alert_processor.py` - Tests for the alert processor Lambda function
- `test_summary_generator.py` - Tests for the summary generator Lambda function

## Adding New Tests

When adding new tests, follow these guidelines:

1. Use the existing fixtures in `conftest.py` or add new ones as needed
2. Mock all external dependencies like AWS services and API calls
3. Test both success and failure scenarios
4. Verify proper error handling and logging
5. Test all conditional logic paths

## Local Testing with SAM

For more comprehensive testing that includes AWS interactions, you can use AWS SAM CLI to test locally:

```bash
sam local invoke AlertProcessorFunction --event tests/events/sample_alert.json
sam local invoke SummaryGeneratorFunction --event tests/events/schedule_event.json
```

## Mocked APIs

The test suite mocks the following external dependencies:

1. **Slack API** - `SlackClient` is mocked to avoid real API calls
2. **Microsoft Defender API** - `DefenderClient` is mocked to return sample alerts
3. **AWS Secrets Manager** - `get_secrets` is mocked to return dummy credentials
4. **Message Formatters** - Formatting functions are mocked to return sample message blocks

This approach ensures tests are fast, reliable, and don't require real credentials. 