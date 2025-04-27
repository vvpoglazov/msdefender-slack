"""
Microsoft Defender Slack Notification System - Lambda Functions
"""

# Lambda functions package 

# Lambda Function handlers
from .summary_generator import handler as summary_lambda_handler
from .vulnerability_reporter import handler as vulnerability_lambda_handler 