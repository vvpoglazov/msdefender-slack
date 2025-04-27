# Microsoft Defender Slack Notification System

## Project Brief

This project aims to build a notification system that integrates Microsoft Defender security alerts with Slack. The system will receive alerts from Microsoft Defender's webhook API, process them, and deliver formatted notifications to designated Slack channels. It will also generate scheduled daily summary reports of high and critical severity threats.

## Core Requirements

1. **Real-time Notifications**: Receive and process Microsoft Defender security alerts in real-time and deliver them to Slack.
2. **Daily Summary Reports**: Generate and deliver daily summary reports of security threats at 9:00 AM on working days.
3. **Monday Reports**: Include the past 72 hours of threats in Monday reports to cover weekend activity.
4. **Weekday Reports**: Include the past 24 hours of threats in reports for Tuesday through Friday.
5. **Severity Filtering**: Focus on high and critical severity threats for both real-time notifications and summary reports.
6. **Well-Formatted Messages**: Design readable Slack messages with appropriate severity indicators.

## Technical Stack

1. **AWS Services**: 
   - Lambda for serverless processing
   - API Gateway for webhook reception
   - CloudWatch for monitoring and scheduling
   - Secrets Manager for secure API token storage
   - EventBridge for scheduled tasks

2. **Infrastructure as Code**: 
   - Terraform for infrastructure management
   - CI/CD pipeline for automated deployment

3. **External APIs**:
   - Microsoft Defender API for security alerts
   - Slack API for notification delivery

## Goals

1. Create a reliable, secure system for delivering security alerts from Microsoft Defender to Slack.
2. Ensure high-priority security threats are promptly communicated to the security team.
3. Provide convenient daily summaries of security threats to maintain awareness.
4. Implement infrastructure as code for consistent, repeatable deployments.
5. Build a maintainable, well-documented system that can be extended in the future. 