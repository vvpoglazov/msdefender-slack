import json
import os
import logging
import datetime
import traceback
from typing import Dict, List, Any, Optional

# Use absolute imports
from src.lib.secret_manager import get_secrets
from src.lib.slack_client import SlackClient
from src.lib.defender_client import DefenderClient
from src.lib.summary_formatter import format_vulnerabilities_summary

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

class Config:
    """Configuration class for summary generator."""
    
    # Environment Variable Keys
    ENV_SLACK_CHANNEL = 'SLACK_CHANNEL'
    ENV_SEVERITY_FILTER = 'VULNERABILITY_SEVERITY_FILTER'
    
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
    """Main class for generating Microsoft Defender vulnerability summary reports."""
    
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
    
    def fetch_vulnerabilities(self, time_range_hours: int, severity_filter: List[str] = None) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch vulnerabilities from Microsoft Defender for the specified time range.
        
        Args:
            time_range_hours: Time range in hours.
            severity_filter: List of severity levels to include (default ["Critical", "High"])
            
        Returns:
            List of vulnerability objects or None if fetching fails.
        """
        logger.info(f"Fetching vulnerabilities for the past {time_range_hours} hours")
        
        # Set default severity filter if none provided
        if severity_filter is None:
            severity_filter = ["Critical", "High"]
        
        # Ensure client is initialized
        if not self.defender_client:
            logger.error("Defender client not initialized during fetch_vulnerabilities call.")
            return None
            
        # Call Defender API to get vulnerabilities
        vulnerabilities = self.defender_client.get_vulnerabilities(
            hours_lookback=time_range_hours,
            severity_filter=severity_filter
        )
        
        return vulnerabilities
    
    def send_error_notification(self, slack_channel: str, error_message: str) -> None:
        """
        Send an error notification to Slack.
        
        Args:
            slack_channel: Slack channel to send the notification to.
            error_message: Error message to include in the notification.
        """
        if not self.slack_client:
            logger.error("Cannot send error notification: Slack client not initialized.")
            return
            
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "❌ Microsoft Defender Summary Error",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error generating Microsoft Defender vulnerability summary:*\n{error_message}"
                }
            }
        ]
        
        try:
            self.slack_client.post_message(slack_channel, "Microsoft Defender Summary Error", blocks)
            logger.info(f"Sent error notification to Slack channel {slack_channel}")
        except Exception as e:
            logger.exception(f"Failed to send error notification to Slack: {e}")
    
    def generate_summary(self, slack_channel: str, severity_filter: List[str] = None) -> Dict[str, Any]:
        """
        Generate and send a vulnerability summary report to Slack.
        
        Args:
            slack_channel: Slack channel to send the summary to.
            severity_filter: List of severity levels to include (default ["Critical", "High"]).
            
        Returns:
            API response dictionary.
        """
        # Determine time range for report (72 hours for Monday, 24 hours otherwise)
        time_range_hours = self.determine_time_range()
        
        # Fetch vulnerabilities from Microsoft Defender
        vulnerabilities = self.fetch_vulnerabilities(time_range_hours, severity_filter)
        
        # Handle potential fetch error
        if vulnerabilities is None:
            error_msg = "Failed to fetch vulnerabilities from Defender. Aborting summary generation."
            logger.error(error_msg)
            # Send an error notification to Slack
            self.send_error_notification(slack_channel, error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
        
        logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities from Defender for the time range.")

        # If no vulnerabilities, send a simple message
        if not vulnerabilities:
            logger.info(f"No vulnerabilities found matching severity filter: {severity_filter}")
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"✅ {self.determine_day_type()} Microsoft Defender Vulnerability Summary",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*No {', '.join(severity_filter)} vulnerabilities found in the past {time_range_hours} hours.*"
                    }
                }
            ]
            
            if self.slack_client:
                self.slack_client.post_message(
                    channel=slack_channel,
                    text=f"No {', '.join(severity_filter)} vulnerabilities found",
                    blocks=blocks
                )
                logger.info(f"Sent 'no vulnerabilities' notification to Slack channel {slack_channel}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No vulnerabilities found matching criteria'})
            }
        
        try:
            # Format vulnerabilities summary for Slack
            formatted_summary = format_vulnerabilities_summary(
                vulnerabilities, 
                period_hours=time_range_hours,
                report_type=self.determine_day_type()
            )
            
            # Send summary to Slack
            if self.slack_client and formatted_summary:
                response = self.slack_client.post_message(
                    channel=slack_channel,
                    text=f"Microsoft Defender Vulnerability Summary",
                    blocks=formatted_summary
                )
                
                if response and response.get('ok'):
                    logger.info(f"Successfully sent vulnerability summary to Slack channel {slack_channel}")
                else:
                    logger.error(f"Failed to send vulnerability summary to Slack: {response}")
                    return {
                        'statusCode': 500,
                        'body': json.dumps({'message': f'Failed to send to Slack: {response}'})
                    }
            else:
                error_msg = "Failed to format summary or Slack client not initialized"
                logger.error(error_msg)
                return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
                
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Successfully sent vulnerability summary to Slack',
                    'vulnerability_count': len(vulnerabilities)
                })
            }
            
        except Exception as e:
            error_msg = f"Error generating or sending vulnerability summary: {str(e)}"
            logger.exception(error_msg)
            # Send an error notification to Slack
            self.send_error_notification(slack_channel, f"{error_msg}\n\n{traceback.format_exc()}")
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}

# Create a global instance of the generator
generator = SummaryGenerator()

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for generating a Microsoft Defender vulnerability summary.
    
    Args:
        event: Lambda event
        context: Lambda context
        
    Returns:
        API Gateway proxy response (statusCode, body)
    """
    try:
        # Initialize the generator if not already done
        generator.initialize()
        
        # Ensure clients are initialized
        if not generator.defender_client:
            error_msg = "Defender client could not be initialized. Check secrets."
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
            
        if not generator.slack_client:
            error_msg = "Slack client could not be initialized. Check secrets."
            logger.error(error_msg)
            return {'statusCode': 500, 'body': json.dumps({'message': error_msg})}
        
        # Get configuration
        slack_channel = Config.get_slack_channel()
        severity_filter = Config.get_severity_filter()
        
        # Convert severity filter to proper case for API
        formatted_severity_filter = [s.capitalize() for s in severity_filter]
        
        logger.info(f"Generating vulnerability summary with severity filter: {formatted_severity_filter}")
        
        # Generate and send summary
        return generator.generate_summary(slack_channel, formatted_severity_filter)
        
    except Exception as e:
        error_msg = f"Fatal error in summary generator handler: {str(e)}"
        logger.exception(error_msg)
        return {'statusCode': 500, 'body': json.dumps({'message': error_msg})} 