import json
import os
import logging
import datetime
from typing import Dict, List, Any, Optional, Union

# Use absolute imports
from src.lib.secret_manager import get_secrets
from src.lib.slack_client import SlackClient
from src.lib.defender_client import DefenderClient
from src.lib.summary_formatter import format_summary

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

class Config:
    """Configuration class for summary generator."""
    
    # Environment Variable Keys
    ENV_SLACK_CHANNEL = 'SLACK_CHANNEL'
    ENV_SEVERITY_FILTER = 'ALERT_SEVERITY_FILTER'
    
    # Defaults
    DEFAULT_SLACK_CHANNEL = 'security-alerts'
    DEFAULT_SEVERITY_FILTER = ['high', 'critical']
    
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

class SummaryGenerator:
    """Main class for generating Microsoft Defender summary reports."""
    
    def __init__(self):
        self.secrets = None
        self.slack_client = None
        self.defender_client = None
        self.defender_tenant_id = None
        self.initialized = False
    
    def initialize(self) -> None:
        """Initialize secrets and clients if not already done."""
        if self.initialized:
            return
            
        logger.info("Initializing summary generator...")
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
            
        # Initialize Defender client
        client_id = self.secrets.get('microsoft_defender_client_id')
        client_secret = self.secrets.get('microsoft_defender_client_secret')
        
        if client_id and client_secret and self.defender_tenant_id:
            logger.info("Initializing Defender client...")
            self.defender_client = DefenderClient(
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=self.defender_tenant_id
            )
        else:
            logger.error("Defender client credentials or Tenant ID missing in secrets.")
            
        self.initialized = True
    
    def determine_day_type(self) -> str:
        """Determine if it's a Weekend (for Monday run) or Daily report."""
        # Use UTC time for consistency with scheduling
        current_day_utc = datetime.datetime.utcnow().strftime('%A')
        return "Weekend" if current_day_utc.lower() == 'monday' else "Daily"
    
    def determine_time_range(self) -> int:
        """
        Determine the time range in hours based on the current day (UTC).
        72 hours for Monday (covers weekend), 24 hours otherwise.
        """
        return 72 if self.determine_day_type() == "Weekend" else 24
    
    def fetch_alerts(self, time_range_hours: int) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch alerts from Microsoft Defender for the specified time range.
        
        Args:
            time_range_hours: Time range in hours.
            
        Returns:
            List of alert objects or None if fetching fails.
        """
        # Calculate the start time based on the time range (UTC)
        end_time_utc = datetime.datetime.utcnow()
        start_time_utc = end_time_utc - datetime.timedelta(hours=time_range_hours)
        
        # Format as ISO 8601 string with Z for UTC
        start_time_str = start_time_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time_str = end_time_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        logger.info(f"Fetching alerts from {start_time_str} to {end_time_str}")
        
        # Ensure client is initialized
        if not self.defender_client:
            logger.error("Defender client not initialized during fetch_alerts call.")
            return None
            
        # Call Defender API to get alerts
        alerts = self.defender_client.get_alerts(start_time=start_time_str, end_time=end_time_str)
        return alerts
    
    def filter_alerts_by_severity(self, alerts: List[Dict[str, Any]], severity_filter: List[str]) -> List[Dict[str, Any]]:
        """
        Filter alerts by severity based on the provided filter list.
        
        Args:
            alerts: List of alert objects.
            severity_filter: List of lowercase severity strings to include.
            
        Returns:
            Filtered list of alert objects.
        """
        if not alerts:
            return []
            
        filtered = [
            alert for alert in alerts 
            if alert.get('alertSeverity', '').lower() in severity_filter
        ]
        return filtered
    
    def send_no_alerts_message(self, slack_channel: str, time_range_hours: int, severity_filter_str: str) -> Dict[str, Any]:
        """
        Send a message to Slack when no alerts are found.
        
        Args:
            slack_channel: Slack channel to send the message to.
            time_range_hours: Time range in hours that was checked.
            severity_filter_str: String representation of severity filter.
            
        Returns:
            API response dictionary.
        """
        logger.info(f"No alerts matched severity filter for the past {time_range_hours} hours.")
        message_blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Microsoft Defender {self.determine_day_type()} Security Summary",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*No alerts matching severity levels '{severity_filter_str}' were detected in the past {time_range_hours} hours.*"
                }
            }
        ]
        
        response = self.slack_client.post_message(
            channel=slack_channel,
            blocks=message_blocks
        )
        
        if response and response.get("ok"):
            logger.info("'No alerts found' message sent to Slack.")
            return {'statusCode': 200, 'body': json.dumps({'message': 'No matching alerts to report'})}
        else:
            error_msg = f"Failed to send 'No alerts found' message to Slack: {response}"
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
    
    def send_error_notification(self, channel: str, message: str) -> None:
        """
        Send an error notification to Slack.
        
        Args:
            channel: Slack channel to send the message to.
            message: Error message to send.
        """
        if not self.slack_client:
            logger.error("Cannot send error notification: Slack client not initialized.")
            return
            
        try:
            error_blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":warning: *Error in MS Defender Slack Notifier*\n> {message}"
                    }
                }
            ]
            self.slack_client.post_message(channel=channel, blocks=error_blocks, text=f"Error: {message}")
            logger.info(f"Sent error notification to Slack channel {channel}.")
        except Exception as notify_err:
            logger.exception(f"Failed to send error notification to Slack: {notify_err}")
    
    def generate_summary(self, slack_channel: str, severity_filter: List[str]) -> Dict[str, Any]:
        """
        Generate and send a summary report to Slack.
        
        Args:
            slack_channel: Slack channel to send the summary to.
            severity_filter: List of severity levels to include.
            
        Returns:
            API response dictionary.
        """
        # Determine time range for report (72 hours for Monday, 24 hours otherwise)
        time_range_hours = self.determine_time_range()
        
        # Fetch alerts from Microsoft Defender
        alerts = self.fetch_alerts(time_range_hours)
        
        # Handle potential fetch error
        if alerts is None:
            error_msg = "Failed to fetch alerts from Defender. Aborting summary generation."
            logger.error(error_msg)
            # Send an error notification to Slack
            self.send_error_notification(slack_channel, error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
        
        logger.info(f"Fetched {len(alerts)} total alerts from Defender for the time range.")

        # Filter alerts by severity
        filtered_alerts = self.filter_alerts_by_severity(alerts, severity_filter)
        logger.info(f"Found {len(filtered_alerts)} alerts matching severity filter: {severity_filter}")
        
        # Format and send summary
        if filtered_alerts:
            message_blocks = format_summary(filtered_alerts, time_range_hours)
            response = self.slack_client.post_message(
                channel=slack_channel,
                blocks=message_blocks
            )
            
            if response and response.get("ok"):
                logger.info(f"Summary report sent successfully to Slack channel {slack_channel}.")
                return {
                    'statusCode': 200,
                    'body': json.dumps({'message': f'Summary report sent with {len(filtered_alerts)} alerts'})
                }
            else:
                error_msg = f"Failed to send summary report to Slack: {response}"
                logger.error(error_msg)
                return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
        else:
            # No alerts matching filter found, send informative message
            severity_filter_str = ",".join(severity_filter)
            return self.send_no_alerts_message(slack_channel, time_range_hours, severity_filter_str)

# Create a global instance of the generator
generator = SummaryGenerator()

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for generating daily summary reports, triggered by EventBridge.
    
    Args:
        event: EventBridge scheduled event (content not typically used)
        context: Lambda context object
        
    Returns:
        Dictionary with statusCode and message body.
    """
    logger.info(f"Summary generation triggered. Event: {event}")
    try:
        # Initialize generator if not already done
        generator.initialize()
        
        # Ensure clients initialized
        if not generator.slack_client:
            error_msg = "Slack client could not be initialized."
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
            
        if not generator.defender_client:
            error_msg = "Defender client could not be initialized."
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}

        # Get configuration
        slack_channel = Config.get_slack_channel()
        severity_filter = Config.get_severity_filter()
        logger.info(f"Filtering for severities: {severity_filter}")

        # Generate and send summary
        return generator.generate_summary(slack_channel, severity_filter)
        
    except Exception as e:
        logger.exception(f"Fatal error generating summary: {e}")
        # Send error notification if possible
        if generator.slack_client:
            generator.send_error_notification(
                Config.get_slack_channel(),
                f"An error occurred during summary generation: {e}"
            )
        # Return error to Lambda runtime
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Internal server error generating summary: {str(e)}'})
        } 