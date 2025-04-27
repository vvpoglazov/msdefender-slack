import json
import os
import logging
from typing import Dict, Any, List, Optional, Union

# Use absolute imports within the same package if running as a module/package
# If running as script, relative imports might be needed depending on structure
# Assuming deployment zips the 'src' directory content
from src.lib.secret_manager import get_secrets
from src.lib.slack_client import SlackClient
from src.lib.alert_formatter import format_alert

# Configure logging
logger = logging.getLogger(__name__) # Use named logger
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

class Config:
    """Configuration class for alert processor."""
    
    # Environment Variable Keys
    ENV_SLACK_CHANNEL = 'SLACK_CHANNEL'
    ENV_SEVERITY_FILTER = 'ALERT_SEVERITY_FILTER'
    ENV_PROJECT_NAME = 'PROJECT_NAME'
    
    # Defaults
    DEFAULT_SLACK_CHANNEL = 'security-alerts'
    DEFAULT_SEVERITY_FILTER = ['high', 'critical']
    DEFAULT_PROJECT_NAME = 'msdefender-slack'
    
    @classmethod
    def get_slack_channel(cls) -> str:
        """Get Slack channel from environment or default."""
        return os.environ.get(cls.ENV_SLACK_CHANNEL, cls.DEFAULT_SLACK_CHANNEL)
    
    @classmethod
    def get_severity_filter(cls) -> List[str]:
        """Get severity filter list from environment or default."""
        severity_filter_str = os.environ.get(cls.ENV_SEVERITY_FILTER, 
                                            ",".join(cls.DEFAULT_SEVERITY_FILTER))
        return [s.strip().lower() for s in severity_filter_str.split(',') if s.strip()]
        
    @classmethod
    def get_project_name(cls) -> str:
        """Get project name from environment or default."""
        return os.environ.get(cls.ENV_PROJECT_NAME, cls.DEFAULT_PROJECT_NAME)

class AlertProcessor:
    """Main class for processing Microsoft Defender alerts."""
    
    def __init__(self):
        self.secrets = None
        self.slack_client = None
        self.defender_tenant_id = None
        self.initialized = False
    
    def initialize(self) -> None:
        """Initialize secrets and clients."""
        if self.initialized:
            return
            
        logger.info("Initializing alert processor...")
        self.secrets = get_secrets()
        
        # Get tenant ID for DefenderClient
        self.defender_tenant_id = self.secrets.get('microsoft_defender_tenant_id')
        if not self.defender_tenant_id:
            logger.error("Microsoft Defender Tenant ID not found in secrets!")
            
        # Initialize Slack client
        slack_token = self.secrets.get('slack_api_token')
        if slack_token:
            logger.info("Initializing Slack client...")
            self.slack_client = SlackClient(slack_token)
        else:
            logger.error("Slack API token not found in secrets. Cannot initialize Slack client.")
            
        self.initialized = True
        
    def validate_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Validate that the alert data contains required fields.
        
        Args:
            alert_data: Parsed alert data dictionary.
            
        Returns:
            True if the alert is valid, False otherwise.
        """
        required_fields = ['id', 'alertSeverity', 'title']
        for field in required_fields:
            if field not in alert_data:
                logger.error(f"Alert missing required field: {field}")
                return False
        return True
    
    def should_process_alert(self, alert_data: Dict[str, Any], severity_filter: List[str]) -> bool:
        """
        Determine if the alert should be processed based on severity against the filter list.
        
        Args:
            alert_data: Parsed alert data dictionary.
            severity_filter: List of lowercase severity strings to process.
            
        Returns:
            True if the alert severity matches the filter, False otherwise.
        """
        if not alert_data:
            return False
            
        severity = alert_data.get('alertSeverity', '').lower()
        
        if not severity:
            logger.warning(f"Alert ID {alert_data.get('id', 'N/A')} has missing or empty severity.")
            return False
            
        # Process if severity is in the configured list
        return severity in severity_filter
    
    def parse_alert(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse the Microsoft Defender alert from the API Gateway event body.
        
        Args:
            event: API Gateway proxy event
            
        Returns:
            Parsed alert data dictionary or None if parsing fails.
        """
        try:
            # API Gateway proxy integration wraps the original request body in event['body']
            if 'body' not in event or not event['body']:
                logger.error("No body found in API Gateway event.")
                return None
                
            body_str = event['body']
            logger.debug(f"Raw event body: {body_str}")
            alert_data = json.loads(body_str)
            
            if not isinstance(alert_data, dict):
                logger.error(f"Parsed body is not a dictionary: {type(alert_data)}")
                return None
                
            if not self.validate_alert(alert_data):
                return None
                
            logger.info(f"Successfully parsed alert data. ID: {alert_data.get('id', 'N/A')}")
            return alert_data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decoding failed: {e}. Body received: {event.get('body', '[Not Found]')[:500]}")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error parsing alert: {e}")
            return None
            
    def process_alert(self, alert_data: Dict[str, Any], severity_filter: List[str], slack_channel: str) -> Dict[str, Any]:
        """
        Process an alert and send it to Slack if it meets severity criteria.
        
        Args:
            alert_data: The parsed alert data.
            severity_filter: List of severity levels to process.
            slack_channel: Slack channel to send the alert to.
            
        Returns:
            API Gateway response dictionary.
        """
        # Check if alert meets severity criteria
        if not self.should_process_alert(alert_data, severity_filter):
            logger.info(f"Alert ID {alert_data.get('id', 'N/A')} severity '{alert_data.get('alertSeverity')}' "
                        f"does not meet filter criteria, skipping.")
            return {'statusCode': 200, 'body': json.dumps({'message': 'Alert skipped (severity filter)'})}
        
        logger.info(f"Processing alert ID: {alert_data.get('id', 'N/A')}")
        # Format the alert for Slack
        message_blocks = format_alert(alert_data)
        
        # Send alert to Slack
        response = self.slack_client.post_message(
            channel=slack_channel,
            blocks=message_blocks
        )
        
        # Check Slack API response
        if response and response.get("ok"):
            logger.info(f"Alert sent successfully to Slack channel {slack_channel}.")
            return {'statusCode': 200, 'body': json.dumps({'message': 'Alert processed successfully'})}
        else:
            error_msg = f"Failed to send alert to Slack: {response}"
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}

# Create a global instance of the processor
processor = AlertProcessor()

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing Microsoft Defender alerts via API Gateway.
    
    Args:
        event: API Gateway proxy event containing the webhook payload
        context: Lambda context object
        
    Returns:
        API Gateway proxy response (statusCode, body)
    """
    try:
        # Initialize processor if not already done
        processor.initialize()
        
        # Ensure Slack client initialized
        if not processor.slack_client:
            error_msg = "Slack client could not be initialized. Check secrets."
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}

        # Get configuration
        slack_channel = Config.get_slack_channel()
        severity_filter = Config.get_severity_filter()
        logger.info(f"Filtering for severities: {severity_filter}")

        # Parse the alert from the webhook payload
        alert_data = processor.parse_alert(event)
        if not alert_data:
            # Error already logged in parse_alert
            return {'statusCode': 400, 'body': json.dumps({'message': 'Invalid alert payload'})}
        
        # Process the alert and return the result
        return processor.process_alert(alert_data, severity_filter, slack_channel)
        
    except Exception as e:
        logger.exception(f"Fatal error processing alert: {e}")
        # Return generic error to API Gateway
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Internal server error processing alert: {str(e)}'})
        } 