# Product Context

## Why This Project Exists

Security teams need timely access to threat information to respond effectively to security incidents. Microsoft Defender provides robust threat detection capabilities, but the default notification mechanisms may not integrate well with a team's existing communication workflows. By connecting Microsoft Defender alerts to Slack, this project ensures that:

1. Security threats are immediately visible in the team's primary communication platform.
2. Critical alerts are not missed due to email overload or delayed viewing.
3. The security team can quickly collaborate on and respond to threats.
4. There is a regular cadence of security awareness through daily summaries.

## Problems This Project Solves

1. **Alert Visibility**: Security alerts in isolated systems may go unnoticed. Bringing them into Slack increases visibility and awareness.
2. **Information Overload**: By filtering for high and critical severity threats, the system focuses attention on what matters most.
3. **Context Switching**: Security teams no longer need to constantly check multiple platforms for alerts.
4. **Weekend Coverage**: The Monday 72-hour report ensures that weekend threats are properly reviewed.
5. **Notification Consistency**: Standardized message formats make alerts easier to understand and act upon.
6. **Manual Reporting**: Eliminates the need for manual compilation of daily security summaries.

## How It Should Work

1. **For Real-time Alerts**:
   - Microsoft Defender detects a security threat
   - An alert is sent via webhook to the AWS API Gateway
   - Lambda function processes the alert
   - If the alert meets severity criteria (high or critical), it is formatted and sent to the designated Slack channel
   - The alert appears in Slack with appropriate severity indicators and relevant details

2. **For Daily Summaries**:
   - At 9:00 AM on working days, EventBridge triggers a Lambda function
   - On Mondays, the function retrieves alerts from the past 72 hours
   - On other weekdays, it retrieves alerts from the past 24 hours
   - The function categorizes threats and generates a summary
   - The summary is formatted and posted to the designated Slack channel

## User Experience Goals

1. **Clarity**: Alert notifications should clearly indicate severity, affected resources, and threat type at a glance.
2. **Actionability**: Provide enough information for immediate triage without overwhelming detail.
3. **Consistency**: Maintain consistent formatting across different types of alerts.
4. **Timeliness**: Deliver real-time alerts with minimal delay.
5. **Relevance**: Filter out low-priority alerts to prevent alert fatigue.
6. **Accessibility**: Ensure information is easily accessible and understandable by the security team.
7. **Reliability**: Security team should trust that all important alerts will be delivered.

## Key Stakeholders

1. **Security Operations Team**: Primary users who will receive and act on the alerts.
2. **Security Management**: Will use daily summaries to understand security posture.
3. **IT Operations**: May need to respond to specific infrastructure-related threats.
4. **Compliance Team**: May use alert history for compliance reporting. 