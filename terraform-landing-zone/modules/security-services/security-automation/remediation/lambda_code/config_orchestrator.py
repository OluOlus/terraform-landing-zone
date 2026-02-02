#!/usr/bin/env python3
"""
Config Orchestrator Lambda Function
Routes AWS Config compliance changes to appropriate remediation functions
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
config_client = boto3.client('config')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_BUCKET = os.environ.get('REMEDIATION_BUCKET')
S3_REMEDIATION_FUNCTION = os.environ.get('S3_REMEDIATION_FUNCTION')
VOLUMES_REMEDIATION_FUNCTION = os.environ.get('VOLUMES_REMEDIATION_FUNCTION')
TAGGING_REMEDIATION_FUNCTION = os.environ.get('TAGGING_REMEDIATION_FUNCTION')

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for Config orchestration
    
    Args:
        event: Lambda event containing Config compliance change
        context: Lambda context object
        
    Returns:
        Dict containing orchestration results
    """
    try:
        logger.info(f"Starting Config orchestration. Event: {json.dumps(event)}")
        
        # Extract compliance change from event
        compliance_change = extract_compliance_change(event)
        if not compliance_change:
            logger.error("No Config compliance change found in event")
            return create_response(False, "No Config compliance change found in event")
        
        logger.info(f"Processing Config compliance change: {compliance_change.get('configRuleName', 'unknown')}")
        
        # Process the compliance change
        orchestration_result = process_config_compliance_change(compliance_change)
        
        # Send notification
        send_notification(compliance_change, orchestration_result)
        
        logger.info(f"Config orchestration completed. Success: {orchestration_result['success']}")
        
        return create_response(
            orchestration_result['success'],
            f"Config orchestration completed. Success: {orchestration_result['success']}",
            orchestration_result
        )
        
    except Exception as e:
        logger.error(f"Config orchestration failed: {str(e)}")
        send_error_notification(str(e))
        return create_response(False, f"Config orchestration failed: {str(e)}")

def extract_compliance_change(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract Config compliance change from event"""
    try:
        # Direct compliance change in event
        if 'configRuleName' in event:
            return event
        
        # EventBridge event format
        if 'source' in event and event['source'] == 'config':
            return event.get('detail', {})
        
        # Config rule compliance change format
        if 'detail' in event and 'configRuleName' in event['detail']:
            return event['detail']
        
        return None
        
    except Exception as e:
        logger.error(f"Error extracting Config compliance change: {str(e)}")
        return None

def process_config_compliance_change(compliance_change: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a Config compliance change and route to appropriate remediation
    
    Args:
        compliance_change: Config compliance change event
        
    Returns:
        Dict containing processing results
    """
    result = {
        'config_rule_name': compliance_change.get('configRuleName', 'unknown'),
        'resource_type': compliance_change.get('resourceType', 'unknown'),
        'resource_id': compliance_change.get('resourceId', 'unknown'),
        'compliance_type': compliance_change.get('newEvaluationResult', {}).get('complianceType', 'unknown'),
        'success': False,
        'remediation_function': None,
        'remediation_result': None,
        'error': None
    }
    
    try:
        logger.info(f"Processing compliance change: {result['config_rule_name']} - {result['resource_type']} - {result['compliance_type']}")
        
        # Only process NON_COMPLIANT resources
        if result['compliance_type'] != 'NON_COMPLIANT':
            result['success'] = True
            result['error'] = f"Resource is {result['compliance_type']}, no remediation needed"
            logger.info(f"Resource {result['resource_id']} is {result['compliance_type']}, skipping remediation")
            return result
        
        # Determine remediation function based on Config rule
        remediation_function = determine_remediation_function(compliance_change)
        
        if not remediation_function:
            result['error'] = "No appropriate remediation function found"
            logger.warning(f"No remediation function found for Config rule {result['config_rule_name']}")
            return result
        
        result['remediation_function'] = remediation_function
        
        # Invoke remediation function
        remediation_result = invoke_remediation_function(remediation_function, compliance_change)
        result['remediation_result'] = remediation_result
        
        if remediation_result and remediation_result.get('success', False):
            result['success'] = True
            logger.info(f"Successfully processed compliance change for {result['resource_id']} with {remediation_function}")
        else:
            result['error'] = remediation_result.get('message', 'Unknown error') if remediation_result else 'No response from remediation function'
            logger.error(f"Failed to process compliance change for {result['resource_id']}: {result['error']}")
        
        # Update Config evaluation result
        update_config_result = update_config_evaluation(compliance_change, result)
        if not update_config_result['success']:
            logger.warning(f"Failed to update Config evaluation: {update_config_result['error']}")
        
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"Error processing compliance change for {result['resource_id']}: {str(e)}")
    
    return result

def determine_remediation_function(compliance_change: Dict[str, Any]) -> Optional[str]:
    """
    Determine which remediation function to use based on the Config rule
    
    Args:
        compliance_change: Config compliance change event
        
    Returns:
        Name of the remediation function to invoke
    """
    try:
        config_rule_name = compliance_change.get('configRuleName', '').lower()
        resource_type = compliance_change.get('resourceType', '')
        resource_id = compliance_change.get('resourceId', '')
        
        logger.info(f"Determining remediation function for rule: {config_rule_name}, resource: {resource_type}")
        
        # S3 related rules
        s3_rules = [
            's3-bucket-public-access-prohibited',
            's3-bucket-public-read-prohibited',
            's3-bucket-public-write-prohibited',
            's3-bucket-ssl-requests-only',
            's3-bucket-server-side-encryption-enabled',
            's3-bucket-logging-enabled'
        ]
        
        if any(rule in config_rule_name for rule in s3_rules) or resource_type == 'AWS::S3::Bucket':
            if S3_REMEDIATION_FUNCTION:
                logger.info(f"Routing Config rule {config_rule_name} to S3 remediation function")
                return S3_REMEDIATION_FUNCTION
        
        # EBS/EC2 volume related rules
        volume_rules = [
            'ec2-ebs-encryption-by-default',
            'encrypted-volumes',
            'ebs-encrypted-volumes',
            'ec2-volume-inuse-check'
        ]
        
        if any(rule in config_rule_name for rule in volume_rules) or resource_type == 'AWS::EC2::Volume':
            if VOLUMES_REMEDIATION_FUNCTION:
                logger.info(f"Routing Config rule {config_rule_name} to volumes remediation function")
                return VOLUMES_REMEDIATION_FUNCTION
        
        # Tagging related rules
        tagging_rules = [
            'required-tags',
            'uk-mandatory-tagging',
            'mandatory-tags',
            'tag-compliance',
            'resource-tags-required'
        ]
        
        if any(rule in config_rule_name for rule in tagging_rules):
            if TAGGING_REMEDIATION_FUNCTION:
                logger.info(f"Routing Config rule {config_rule_name} to tagging remediation function")
                return TAGGING_REMEDIATION_FUNCTION
        
        # region-specific compliance rules
        uk_rules = [
            'uk-data-residency',
            'uk-gdpr-compliance',
            'ncsc-cloud-security',
            'cyber-essentials'
        ]
        
        if any(rule in config_rule_name for rule in uk_rules):
            # Route based on resource type for UK rules
            if resource_type == 'AWS::S3::Bucket' and S3_REMEDIATION_FUNCTION:
                return S3_REMEDIATION_FUNCTION
            elif resource_type == 'AWS::EC2::Volume' and VOLUMES_REMEDIATION_FUNCTION:
                return VOLUMES_REMEDIATION_FUNCTION
            elif TAGGING_REMEDIATION_FUNCTION:
                return TAGGING_REMEDIATION_FUNCTION
        
        # AWS managed rules mapping
        aws_managed_rules = {
            'S3_BUCKET_PUBLIC_ACCESS_PROHIBITED': S3_REMEDIATION_FUNCTION,
            'S3_BUCKET_PUBLIC_READ_PROHIBITED': S3_REMEDIATION_FUNCTION,
            'S3_BUCKET_PUBLIC_WRITE_PROHIBITED': S3_REMEDIATION_FUNCTION,
            'S3_BUCKET_SSL_REQUESTS_ONLY': S3_REMEDIATION_FUNCTION,
            'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED': S3_REMEDIATION_FUNCTION,
            'ENCRYPTED_VOLUMES': VOLUMES_REMEDIATION_FUNCTION,
            'EC2_EBS_ENCRYPTION_BY_DEFAULT': VOLUMES_REMEDIATION_FUNCTION,
            'REQUIRED_TAGS': TAGGING_REMEDIATION_FUNCTION
        }
        
        # Check if it's an AWS managed rule
        for aws_rule, function_name in aws_managed_rules.items():
            if aws_rule.lower().replace('_', '-') in config_rule_name:
                if function_name:
                    logger.info(f"Routing AWS managed rule {config_rule_name} to {function_name}")
                    return function_name
        
        logger.warning(f"No remediation function determined for Config rule {config_rule_name}")
        return None
        
    except Exception as e:
        logger.error(f"Error determining remediation function: {str(e)}")
        return None

def invoke_remediation_function(function_name: str, compliance_change: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Invoke the specified remediation function
    
    Args:
        function_name: Name of the Lambda function to invoke
        compliance_change: Config compliance change to pass to the function
        
    Returns:
        Response from the remediation function
    """
    try:
        # Prepare payload for remediation function
        payload = {
            'source': 'config-orchestrator',
            'resourceId': compliance_change.get('resourceId'),
            'resourceType': compliance_change.get('resourceType'),
            'configRuleName': compliance_change.get('configRuleName'),
            'evaluationResult': compliance_change.get('newEvaluationResult', {}),
            'account': compliance_change.get('account'),
            'region': compliance_change.get('region')
        }
        
        logger.info(f"Invoking remediation function {function_name}")
        
        # Invoke the function synchronously
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        # Parse response
        if response['StatusCode'] == 200:
            response_payload = json.loads(response['Payload'].read())
            logger.info(f"Successfully invoked {function_name}")
            return response_payload
        else:
            logger.error(f"Failed to invoke {function_name}. Status code: {response['StatusCode']}")
            return None
        
    except ClientError as e:
        logger.error(f"AWS error invoking {function_name}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error invoking {function_name}: {str(e)}")
        return None

def update_config_evaluation(compliance_change: Dict[str, Any], processing_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update Config evaluation result based on remediation outcome
    
    Args:
        compliance_change: Original compliance change event
        processing_result: Results from processing the compliance change
        
    Returns:
        Dict containing update results
    """
    result = {'success': False, 'error': None}
    
    try:
        config_rule_name = compliance_change.get('configRuleName')
        resource_type = compliance_change.get('resourceType')
        resource_id = compliance_change.get('resourceId')
        
        if not all([config_rule_name, resource_type, resource_id]):
            result['error'] = "Missing required fields for Config evaluation update"
            return result
        
        # Determine new compliance status based on remediation result
        if processing_result['success'] and processing_result.get('remediation_result', {}).get('success', False):
            new_compliance_type = 'COMPLIANT'
            annotation = f"Automated remediation completed successfully by {processing_result['remediation_function']}"
        else:
            new_compliance_type = 'NON_COMPLIANT'
            error_msg = processing_result.get('error', 'Unknown error')
            annotation = f"Automated remediation failed: {error_msg}"
        
        # Put evaluation result
        evaluation = {
            'ComplianceResourceType': resource_type,
            'ComplianceResourceId': resource_id,
            'ComplianceType': new_compliance_type,
            'Annotation': annotation[:256],  # Config has annotation length limits
            'OrderingTimestamp': compliance_change.get('newEvaluationResult', {}).get('resultRecordedTime', 
                                                     compliance_change.get('timestamp', '2023-01-01T00:00:00Z'))
        }
        
        # Note: In a real implementation, you would need the Config rule's result token
        # which is typically available in Config rule evaluations but not in compliance change events
        # For now, we'll log the evaluation that would be submitted
        logger.info(f"Would submit Config evaluation: {json.dumps(evaluation)}")
        
        result['success'] = True
        logger.info(f"Config evaluation update prepared for {resource_id}")
        
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"Error updating Config evaluation: {str(e)}")
    
    return result

def send_notification(compliance_change: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Send notification about Config compliance change processing"""
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return
        
        # Determine notification priority based on rule and resource type
        config_rule_name = compliance_change.get('configRuleName', 'unknown')
        resource_type = compliance_change.get('resourceType', 'unknown')
        
        priority = 'MEDIUM'
        if any(critical_rule in config_rule_name.lower() for critical_rule in [
            'public-access', 'encryption', 'security-group', 'iam'
        ]):
            priority = 'HIGH'
        elif any(low_rule in config_rule_name.lower() for low_rule in [
            'tag', 'naming', 'description'
        ]):
            priority = 'LOW'
        
        message = {
            'event_type': 'CONFIG_COMPLIANCE_CHANGE_PROCESSED',
            'priority': priority,
            'config_rule_name': config_rule_name,
            'resource_type': resource_type,
            'resource_id': result['resource_id'],
            'compliance_type': result['compliance_type'],
            'processing_result': {
                'success': result['success'],
                'remediation_function': result['remediation_function'],
                'error': result['error']
            },
            'remediation_result': result.get('remediation_result'),
            'account': compliance_change.get('account', 'unknown'),
            'region': compliance_change.get('region', 'unknown'),
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        # Use different subject based on priority and outcome
        priority_emoji = {
            'HIGH': 'CRITICAL',
            'MEDIUM': 'WARNING',
            'LOW': 'INFO'
        }.get(priority, 'STANDARD')
        
        outcome = 'Remediated' if result['success'] else 'Failed'
        subject = f"{priority_emoji} Config Compliance - {outcome} - {config_rule_name}"
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent notification for Config compliance change {config_rule_name}")
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")

def send_error_notification(error_message: str) -> None:
    """Send error notification"""
    try:
        if not SNS_TOPIC_ARN:
            return
        
        message = {
            'event_type': 'CONFIG_ORCHESTRATION_ERROR',
            'error_message': error_message,
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Config Orchestration Error",
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