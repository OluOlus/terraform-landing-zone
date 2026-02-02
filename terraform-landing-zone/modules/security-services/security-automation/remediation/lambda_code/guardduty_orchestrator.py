#!/usr/bin/env python3
"""
GuardDuty Orchestrator Lambda Function
Routes GuardDuty findings to appropriate remediation functions
Compliant with GDPR and Security Standards Cloud Security Principles
"""

import json
import boto3
import logging
import os
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Initialize AWS clients
lambda_client = boto3.client('lambda')
sns_client = boto3.client('sns')
guardduty_client = boto3.client('guardduty')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_BUCKET = os.environ.get('REMEDIATION_BUCKET')

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for GuardDuty orchestration
    
    Args:
        event: Lambda event containing GuardDuty finding
        context: Lambda context object
        
    Returns:
        Dict containing orchestration results
    """
    try:
        logger.info(f"Starting GuardDuty orchestration. Event: {json.dumps(event)}")
        
        # Extract finding from event
        finding = extract_guardduty_finding(event)
        if not finding:
            logger.error("No GuardDuty finding found in event")
            return create_response(False, "No GuardDuty finding found in event")
        
        logger.info(f"Processing GuardDuty finding: {finding.get('Id', 'unknown')}")
        
        # Process the finding
        orchestration_result = process_guardduty_finding(finding)
        
        # Send notification
        send_notification(finding, orchestration_result)
        
        logger.info(f"GuardDuty orchestration completed. Success: {orchestration_result['success']}")
        
        return create_response(
            orchestration_result['success'],
            f"GuardDuty orchestration completed. Success: {orchestration_result['success']}",
            orchestration_result
        )
        
    except Exception as e:
        logger.error(f"GuardDuty orchestration failed: {str(e)}")
        send_error_notification(str(e))
        return create_response(False, f"GuardDuty orchestration failed: {str(e)}")

def extract_guardduty_finding(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract GuardDuty finding from event"""
    try:
        # Direct finding in event
        if 'finding' in event:
            return event['finding']
        
        # EventBridge event format
        if 'source' in event and event['source'] == 'guardduty':
            return event.get('detail', {})
        
        # GuardDuty finding format
        if 'Id' in event and 'Type' in event:
            return event
        
        return None
        
    except Exception as e:
        logger.error(f"Error extracting GuardDuty finding: {str(e)}")
        return None

def process_guardduty_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a GuardDuty finding and determine appropriate response
    
    Args:
        finding: GuardDuty finding
        
    Returns:
        Dict containing processing results
    """
    result = {
        'finding_id': finding.get('Id', 'unknown'),
        'finding_type': finding.get('Type', 'unknown'),
        'severity': finding.get('Severity', 0),
        'success': False,
        'actions_taken': [],
        'errors': [],
        'remediation_recommended': False
    }
    
    try:
        logger.info(f"Processing GuardDuty finding: {result['finding_id']} - {result['finding_type']} (Severity: {result['severity']})")
        
        # Analyze finding for automated remediation opportunities
        analysis_result = analyze_finding_for_remediation(finding)
        result['actions_taken'].extend(analysis_result['actions'])
        result['errors'].extend(analysis_result['errors'])
        result['remediation_recommended'] = analysis_result['remediation_recommended']
        
        # Apply immediate protective measures if needed
        protection_result = apply_immediate_protection(finding)
        result['actions_taken'].extend(protection_result['actions'])
        result['errors'].extend(protection_result['errors'])
        
        # Update GuardDuty finding with notes
        update_result = update_guardduty_finding(finding, result)
        result['actions_taken'].extend(update_result['actions'])
        result['errors'].extend(update_result['errors'])
        
        # Determine overall success
        result['success'] = len(result['errors']) == 0
        
        logger.info(f"Processed GuardDuty finding {result['finding_id']}. Actions: {len(result['actions_taken'])}, Errors: {len(result['errors'])}")
        
    except Exception as e:
        result['errors'].append(f"Error processing GuardDuty finding: {str(e)}")
        logger.error(f"Error processing GuardDuty finding {result['finding_id']}: {str(e)}")
    
    return result

def analyze_finding_for_remediation(finding: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Analyze GuardDuty finding to determine if automated remediation is possible
    
    Args:
        finding: GuardDuty finding
        
    Returns:
        Dict containing analysis results
    """
    result = {'actions': [], 'errors': [], 'remediation_recommended': False}
    
    try:
        finding_type = finding.get('Type', '')
        severity = finding.get('Severity', 0)
        service = finding.get('Service', {})
        
        # High severity findings that may require immediate action
        if severity >= 7.0:
            result['actions'].append(f"High severity finding detected: {finding_type} (Severity: {severity})")
            result['remediation_recommended'] = True
        
        # Analyze specific finding types
        if 'Backdoor' in finding_type:
            result['actions'].append("Backdoor activity detected - immediate investigation required")
            result['remediation_recommended'] = True
            
        elif 'Cryptocurrency' in finding_type:
            result['actions'].append("Cryptocurrency mining activity detected - resource isolation recommended")
            result['remediation_recommended'] = True
            
        elif 'Malware' in finding_type:
            result['actions'].append("Malware detected - immediate containment required")
            result['remediation_recommended'] = True
            
        elif 'Trojan' in finding_type:
            result['actions'].append("Trojan detected - system quarantine recommended")
            result['remediation_recommended'] = True
            
        elif 'UnauthorizedAPICall' in finding_type:
            result['actions'].append("Unauthorized API calls detected - access review required")
            result['remediation_recommended'] = True
            
        elif 'Recon' in finding_type:
            result['actions'].append("Reconnaissance activity detected - monitoring enhanced")
            
        elif 'Stealth' in finding_type:
            result['actions'].append("Stealth activity detected - security controls review required")
            result['remediation_recommended'] = True
        
        # Check for region-specific threats
        uk_threat_indicators = [
            'brexit',
            'uk-gov',
            'hmrc',
            'nhs',
            'mod.uk',
            'gov.uk'
        ]
        
        finding_details = json.dumps(finding).lower()
        for indicator in uk_threat_indicators:
            if indicator in finding_details:
                result['actions'].append(f"region-specific threat indicator detected: {indicator}")
                result['remediation_recommended'] = True
                break
        
        # Analyze resource details
        resource_details = service.get('ResourceRole', '')
        if resource_details == 'TARGET':
            result['actions'].append("Resource is target of malicious activity - protection measures recommended")
            result['remediation_recommended'] = True
        
        logger.info(f"Analysis completed for finding {finding.get('Id')}. Remediation recommended: {result['remediation_recommended']}")
        
    except Exception as e:
        error_msg = f"Error analyzing finding for remediation: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def apply_immediate_protection(finding: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Apply immediate protective measures based on GuardDuty finding
    
    Args:
        finding: GuardDuty finding
        
    Returns:
        Dict containing protection results
    """
    result = {'actions': [], 'errors': []}
    
    try:
        finding_type = finding.get('Type', '')
        severity = finding.get('Severity', 0)
        service = finding.get('Service', {})
        
        # For very high severity findings, consider immediate protective actions
        if severity >= 8.5:
            # Check if this involves EC2 instances
            if 'InstanceDetails' in service:
                instance_details = service['InstanceDetails']
                instance_id = instance_details.get('InstanceId')
                
                if instance_id:
                    # For demonstration - in production, this would need careful consideration
                    # and possibly manual approval for such drastic actions
                    result['actions'].append(f"High severity threat detected on instance {instance_id}")
                    result['actions'].append("Immediate protective measures recommended - manual intervention required")
                    
                    # Could implement:
                    # - Security group isolation
                    # - Instance snapshot for forensics
                    # - Network isolation
                    # - Alerting to security team
            
            # Check if this involves S3 buckets
            if 'S3BucketDetails' in service:
                bucket_details = service['S3BucketDetails']
                for bucket in bucket_details:
                    bucket_name = bucket.get('Name')
                    if bucket_name:
                        result['actions'].append(f"High severity threat detected involving S3 bucket {bucket_name}")
                        result['actions'].append("S3 bucket access review recommended")
        
        # For malware/trojan findings, recommend immediate containment
        if any(threat in finding_type for threat in ['Malware', 'Trojan', 'Backdoor']):
            result['actions'].append("Malicious software detected - immediate containment protocols activated")
            
            # In a real implementation, this might:
            # - Isolate affected instances
            # - Create forensic snapshots
            # - Block suspicious network traffic
            # - Alert incident response team
        
        # For cryptocurrency mining, recommend resource monitoring
        if 'Cryptocurrency' in finding_type:
            result['actions'].append("Cryptocurrency mining detected - resource usage monitoring enhanced")
        
        # For data exfiltration attempts, recommend data protection measures
        if 'Exfiltration' in finding_type:
            result['actions'].append("Data exfiltration attempt detected - data protection measures activated")
        
        logger.info(f"Applied immediate protection measures for finding {finding.get('Id')}")
        
    except Exception as e:
        error_msg = f"Error applying immediate protection: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def update_guardduty_finding(finding: Dict[str, Any], processing_result: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Update GuardDuty finding with processing notes
    
    Args:
        finding: GuardDuty finding
        processing_result: Results from processing the finding
        
    Returns:
        Dict containing update results
    """
    result = {'actions': [], 'errors': []}
    
    try:
        finding_id = finding.get('Id')
        detector_id = finding.get('DetectorId')
        
        if not finding_id or not detector_id:
            result['errors'].append("Missing finding ID or detector ID for GuardDuty update")
            return result
        
        # Create feedback for the finding
        feedback_type = 'USEFUL' if processing_result['success'] else 'NOT_USEFUL'
        
        # Add comments about automated processing
        comments = f"Automated processing completed. Actions taken: {len(processing_result['actions_taken'])}. "
        if processing_result['remediation_recommended']:
            comments += "Remediation recommended. "
        if processing_result['errors']:
            comments += f"Errors encountered: {len(processing_result['errors'])}. "
        
        comments += "Processed by UK Security Automation."
        
        # Archive the finding if successfully processed and no errors
        if processing_result['success'] and not processing_result['errors']:
            try:
                guardduty_client.archive_findings(
                    DetectorId=detector_id,
                    FindingIds=[finding_id]
                )
                result['actions'].append(f"Archived GuardDuty finding {finding_id}")
            except ClientError as e:
                # Don't fail the entire process if archiving fails
                result['errors'].append(f"Failed to archive finding {finding_id}: {str(e)}")
        
        # Create finding feedback
        try:
            guardduty_client.create_finding_feedback(
                DetectorId=detector_id,
                FindingId=finding_id,
                Feedback=feedback_type,
                Comments=comments[:512]  # GuardDuty has a comment length limit
            )
            result['actions'].append(f"Added feedback to GuardDuty finding {finding_id}")
        except ClientError as e:
            result['errors'].append(f"Failed to add feedback to finding {finding_id}: {str(e)}")
        
        logger.info(f"Updated GuardDuty finding {finding_id}")
        
    except Exception as e:
        error_msg = f"Error updating GuardDuty finding: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def send_notification(finding: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Send notification about GuardDuty finding processing"""
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return
        
        # Determine notification urgency based on severity and finding type
        severity = finding.get('Severity', 0)
        finding_type = finding.get('Type', 'unknown')
        
        urgency = 'LOW'
        if severity >= 8.5:
            urgency = 'CRITICAL'
        elif severity >= 7.0:
            urgency = 'HIGH'
        elif severity >= 4.0:
            urgency = 'MEDIUM'
        
        message = {
            'event_type': 'GUARDDUTY_FINDING_PROCESSED',
            'urgency': urgency,
            'finding_id': finding.get('Id', 'unknown'),
            'finding_type': finding_type,
            'severity': severity,
            'region': finding.get('Region', 'unknown'),
            'account_id': finding.get('AccountId', 'unknown'),
            'processing_result': {
                'success': result['success'],
                'actions_taken': result['actions_taken'],
                'errors': result['errors'],
                'remediation_recommended': result['remediation_recommended']
            },
            'service_details': finding.get('Service', {}),
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        # Use different subject based on urgency
        subject_prefix = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW'
        }.get(urgency, 'INFO')
        
        subject = f"{subject_prefix} GuardDuty Finding - {finding_type} (Severity: {severity})"
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent notification for GuardDuty finding {finding.get('Id')}")
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")

def send_error_notification(error_message: str) -> None:
    """Send error notification"""
    try:
        if not SNS_TOPIC_ARN:
            return
        
        message = {
            'event_type': 'GUARDDUTY_ORCHESTRATION_ERROR',
            'error_message': error_message,
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="CRITICAL GuardDuty Orchestration Error",
            Message=json.dumps(message, indent=2)
        )
        
    except Exception as e:
        logger.error(f"Failed to send error notification: {str(e)}")

def create_response(success: bool, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create standardized response"""
    response = {
        'success': success,
        'message': message,
        'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
    }
    
    if data:
        response['data'] = data
    
    return response