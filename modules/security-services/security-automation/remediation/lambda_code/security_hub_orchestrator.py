#!/usr/bin/env python3
"""
Security Hub Orchestrator Lambda Function
Routes Security Hub findings to appropriate remediation functions
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
securityhub_client = boto3.client('securityhub')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_BUCKET = os.environ.get('REMEDIATION_BUCKET')
S3_REMEDIATION_FUNCTION = os.environ.get('S3_REMEDIATION_FUNCTION')
VOLUMES_REMEDIATION_FUNCTION = os.environ.get('VOLUMES_REMEDIATION_FUNCTION')
TAGGING_REMEDIATION_FUNCTION = os.environ.get('TAGGING_REMEDIATION_FUNCTION')

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for Security Hub orchestration
    
    Args:
        event: Lambda event containing Security Hub findings
        context: Lambda context object
        
    Returns:
        Dict containing orchestration results
    """
    try:
        logger.info(f"Starting Security Hub orchestration. Event: {json.dumps(event)}")
        
        # Extract findings from event
        findings = extract_findings(event)
        if not findings:
            logger.error("No findings found in event")
            return create_response(False, "No findings found in event")
        
        logger.info(f"Processing {len(findings)} Security Hub findings")
        
        # Process each finding
        orchestration_results = []
        for finding in findings:
            result = process_security_hub_finding(finding)
            orchestration_results.append(result)
        
        # Send summary notification
        send_summary_notification(orchestration_results)
        
        # Calculate overall success
        successful_remediations = sum(1 for result in orchestration_results if result['success'])
        total_findings = len(orchestration_results)
        
        logger.info(f"Security Hub orchestration completed. {successful_remediations}/{total_findings} findings processed successfully")
        
        return create_response(
            successful_remediations == total_findings,
            f"Security Hub orchestration completed. {successful_remediations}/{total_findings} findings processed successfully",
            {'results': orchestration_results}
        )
        
    except Exception as e:
        logger.error(f"Security Hub orchestration failed: {str(e)}")
        send_error_notification(str(e))
        return create_response(False, f"Security Hub orchestration failed: {str(e)}")

def extract_findings(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract Security Hub findings from event"""
    try:
        # Direct findings in event
        if 'findings' in event:
            return event['findings']
        
        # EventBridge event format
        if 'source' in event and event['source'] == 'security-hub':
            return event.get('findings', [])
        
        # Single finding format
        if 'Id' in event and 'ProductArn' in event:
            return [event]
        
        return []
        
    except Exception as e:
        logger.error(f"Error extracting findings: {str(e)}")
        return []

def process_security_hub_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a single Security Hub finding and route to appropriate remediation
    
    Args:
        finding: Security Hub finding
        
    Returns:
        Dict containing processing results
    """
    result = {
        'finding_id': finding.get('Id', 'unknown'),
        'finding_title': finding.get('Title', 'unknown'),
        'success': False,
        'remediation_function': None,
        'remediation_result': None,
        'error': None
    }
    
    try:
        logger.info(f"Processing finding: {result['finding_id']} - {result['finding_title']}")
        
        # Determine remediation function based on finding
        remediation_function = determine_remediation_function(finding)
        
        if not remediation_function:
            result['error'] = "No appropriate remediation function found"
            logger.warning(f"No remediation function found for finding {result['finding_id']}")
            return result
        
        result['remediation_function'] = remediation_function
        
        # Invoke remediation function
        remediation_result = invoke_remediation_function(remediation_function, finding)
        result['remediation_result'] = remediation_result
        
        if remediation_result and remediation_result.get('success', False):
            result['success'] = True
            logger.info(f"Successfully processed finding {result['finding_id']} with {remediation_function}")
        else:
            result['error'] = remediation_result.get('message', 'Unknown error') if remediation_result else 'No response from remediation function'
            logger.error(f"Failed to process finding {result['finding_id']}: {result['error']}")
        
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"Error processing finding {result['finding_id']}: {str(e)}")
    
    return result

def determine_remediation_function(finding: Dict[str, Any]) -> Optional[str]:
    """
    Determine which remediation function to use based on the finding
    
    Args:
        finding: Security Hub finding
        
    Returns:
        Name of the remediation function to invoke
    """
    try:
        # Get finding details
        finding_id = finding.get('Id', '')
        title = finding.get('Title', '').lower()
        description = finding.get('Description', '').lower()
        generator_id = finding.get('GeneratorId', '').lower()
        
        # Check resources in the finding
        resources = finding.get('Resources', [])
        
        # S3 public access violations
        s3_indicators = [
            's3' in title,
            's3' in description,
            's3' in generator_id,
            'bucket' in title,
            'bucket' in description,
            'public' in title and ('read' in title or 'write' in title or 'access' in title),
            any(resource.get('Type') == 'AwsS3Bucket' for resource in resources)
        ]
        
        if any(s3_indicators) and S3_REMEDIATION_FUNCTION:
            logger.info(f"Routing finding {finding_id} to S3 remediation function")
            return S3_REMEDIATION_FUNCTION
        
        # Unencrypted volumes
        volume_indicators = [
            'ebs' in title,
            'volume' in title,
            'encrypt' in title and 'not' in title,
            'unencrypted' in title,
            'unencrypted' in description,
            any(resource.get('Type') == 'AwsEc2Volume' for resource in resources)
        ]
        
        if any(volume_indicators) and VOLUMES_REMEDIATION_FUNCTION:
            logger.info(f"Routing finding {finding_id} to volumes remediation function")
            return VOLUMES_REMEDIATION_FUNCTION
        
        # Untagged resources
        tagging_indicators = [
            'tag' in title and ('missing' in title or 'required' in title or 'mandatory' in title),
            'untagged' in title,
            'untagged' in description,
            'required tags' in description,
            'mandatory tags' in description,
            # Check for specific compliance rules
            'uk-mandatory-tagging' in generator_id,
            'required-tags' in generator_id
        ]
        
        if any(tagging_indicators) and TAGGING_REMEDIATION_FUNCTION:
            logger.info(f"Routing finding {finding_id} to tagging remediation function")
            return TAGGING_REMEDIATION_FUNCTION
        
        # Check for specific Security Hub control IDs
        control_id = finding.get('ProductFields', {}).get('ControlId', '')
        
        # Map specific control IDs to remediation functions
        control_mappings = {
            # S3 controls
            'S3.1': S3_REMEDIATION_FUNCTION,  # S3 Block Public Access
            'S3.2': S3_REMEDIATION_FUNCTION,  # S3 Block Public Read Access
            'S3.3': S3_REMEDIATION_FUNCTION,  # S3 Block Public Write Access
            'S3.8': S3_REMEDIATION_FUNCTION,  # S3 Block Public Access to buckets with sensitive data
            
            # EC2 controls
            'EC2.3': VOLUMES_REMEDIATION_FUNCTION,  # EBS volumes should be encrypted
            'EC2.7': VOLUMES_REMEDIATION_FUNCTION,  # EBS default encryption should be enabled
            
            # General tagging controls
            'Config.1': TAGGING_REMEDIATION_FUNCTION,  # Required tags
        }
        
        if control_id in control_mappings:
            function_name = control_mappings[control_id]
            if function_name:
                logger.info(f"Routing finding {finding_id} with control ID {control_id} to {function_name}")
                return function_name
        
        logger.warning(f"No remediation function determined for finding {finding_id}")
        return None
        
    except Exception as e:
        logger.error(f"Error determining remediation function: {str(e)}")
        return None

def invoke_remediation_function(function_name: str, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Invoke the specified remediation function
    
    Args:
        function_name: Name of the Lambda function to invoke
        finding: Security Hub finding to pass to the function
        
    Returns:
        Response from the remediation function
    """
    try:
        # Prepare payload for remediation function
        payload = {
            'findings': [finding],
            'source': 'security-hub-orchestrator'
        }
        
        logger.info(f"Invoking remediation function {function_name}")
        
        # Invoke the function asynchronously
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',  # Synchronous for better error handling
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

def send_summary_notification(results: List[Dict[str, Any]]) -> None:
    """Send summary notification about orchestration results"""
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return
        
        # Calculate summary statistics
        total_findings = len(results)
        successful_remediations = sum(1 for result in results if result['success'])
        failed_remediations = total_findings - successful_remediations
        
        # Group by remediation function
        function_stats = {}
        for result in results:
            func_name = result.get('remediation_function', 'unknown')
            if func_name not in function_stats:
                function_stats[func_name] = {'total': 0, 'success': 0, 'failed': 0}
            
            function_stats[func_name]['total'] += 1
            if result['success']:
                function_stats[func_name]['success'] += 1
            else:
                function_stats[func_name]['failed'] += 1
        
        # Prepare notification message
        message = {
            'event_type': 'SECURITY_HUB_ORCHESTRATION_SUMMARY',
            'summary': {
                'total_findings': total_findings,
                'successful_remediations': successful_remediations,
                'failed_remediations': failed_remediations,
                'success_rate': f"{(successful_remediations/total_findings*100):.1f}%" if total_findings > 0 else "0%"
            },
            'function_statistics': function_stats,
            'failed_findings': [
                {
                    'finding_id': result['finding_id'],
                    'finding_title': result['finding_title'],
                    'error': result['error']
                }
                for result in results if not result['success']
            ],
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Security Hub Orchestration Summary - {successful_remediations}/{total_findings} successful",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent orchestration summary notification")
        
    except Exception as e:
        logger.error(f"Failed to send summary notification: {str(e)}")

def send_error_notification(error_message: str) -> None:
    """Send error notification"""
    try:
        if not SNS_TOPIC_ARN:
            return
        
        message = {
            'event_type': 'SECURITY_HUB_ORCHESTRATION_ERROR',
            'error_message': error_message,
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Hub Orchestration Error",
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