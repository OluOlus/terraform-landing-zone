#!/usr/bin/env python3
"""
S3 Public Access Remediation Lambda Function
Automatically remediates S3 buckets with public access violations
Compliant with GDPR and Security Standards Cloud Security Principles
"""

import json
import boto3
import logging
import os
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Initialize AWS clients
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
securityhub_client = boto3.client('securityhub')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_BUCKET = os.environ.get('REMEDIATION_BUCKET')
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'
UK_COMPLIANCE_MODE = os.environ.get('UK_COMPLIANCE_MODE', 'true').lower() == 'true'

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for S3 public access remediation
    
    Args:
        event: Lambda event containing S3 bucket information
        context: Lambda context object
        
    Returns:
        Dict containing remediation results
    """
    try:
        logger.info(f"Starting S3 public access remediation. Event: {json.dumps(event)}")
        
        # Extract bucket information from event
        bucket_name = extract_bucket_name(event)
        if not bucket_name:
            logger.error("No bucket name found in event")
            return create_response(False, "No bucket name found in event")
        
        logger.info(f"Processing bucket: {bucket_name}")
        
        # Check if bucket exists and is in specified regions
        if not validate_bucket_location(bucket_name):
            logger.error(f"Bucket {bucket_name} is not in specified regions or does not exist")
            return create_response(False, f"Bucket {bucket_name} is not in specified regions or does not exist")
        
        # Perform remediation
        remediation_results = remediate_s3_public_access(bucket_name)
        
        # Send notification
        send_notification(bucket_name, remediation_results)
        
        # Update Security Hub finding if applicable
        update_security_hub_finding(event, remediation_results)
        
        logger.info("S3 public access remediation completed successfully")
        return create_response(True, "S3 public access remediation completed successfully", remediation_results)
        
    except Exception as e:
        logger.error(f"S3 public access remediation failed: {str(e)}")
        send_error_notification(str(e))
        return create_response(False, f"S3 public access remediation failed: {str(e)}")

def extract_bucket_name(event: Dict[str, Any]) -> Optional[str]:
    """Extract S3 bucket name from various event sources"""
    try:
        # Security Hub finding
        if 'findings' in event:
            for finding in event['findings']:
                if 'Resources' in finding:
                    for resource in finding['Resources']:
                        if resource.get('Type') == 'AwsS3Bucket':
                            return resource.get('Id', '').split('/')[-1]
        
        # Config compliance event
        if 'resourceId' in event:
            return event['resourceId']
        
        # Direct bucket name
        if 'bucket_name' in event:
            return event['bucket_name']
            
        # GuardDuty finding
        if 'finding' in event and 'Service' in event['finding']:
            service = event['finding']['Service']
            if 'ResourceRole' in service and service['ResourceRole'] == 'TARGET':
                if 'RemoteIpDetails' in service:
                    # Extract from GuardDuty S3 related findings
                    pass
        
        return None
        
    except Exception as e:
        logger.error(f"Error extracting bucket name: {str(e)}")
        return None

def validate_bucket_location(bucket_name: str) -> bool:
    """Validate that bucket exists and is in specified regions"""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        
        # None means us-east-1, which is not UK
        if location is None:
            return False
            
        # Check if in specified regions
        uk_regions = ['us-west-2', 'us-east-1']
        return location in uk_regions
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            logger.error(f"Bucket {bucket_name} does not exist")
        else:
            logger.error(f"Error checking bucket location: {str(e)}")
        return False

def remediate_s3_public_access(bucket_name: str) -> Dict[str, Any]:
    """
    Remediate S3 bucket public access violations
    
    Args:
        bucket_name: Name of the S3 bucket to remediate
        
    Returns:
        Dict containing remediation results
    """
    results = {
        'bucket_name': bucket_name,
        'actions_taken': [],
        'errors': [],
        'compliance_status': 'COMPLIANT'
    }
    
    try:
        # 1. Block public access
        block_public_access_result = block_public_access(bucket_name)
        results['actions_taken'].extend(block_public_access_result['actions'])
        results['errors'].extend(block_public_access_result['errors'])
        
        # 2. Remove public bucket policy
        remove_public_policy_result = remove_public_bucket_policy(bucket_name)
        results['actions_taken'].extend(remove_public_policy_result['actions'])
        results['errors'].extend(remove_public_policy_result['errors'])
        
        # 3. Remove public ACLs
        remove_public_acl_result = remove_public_acls(bucket_name)
        results['actions_taken'].extend(remove_public_acl_result['actions'])
        results['errors'].extend(remove_public_acl_result['errors'])
        
        # 4. Apply compliance tags if missing
        apply_uk_tags_result = apply_uk_compliance_tags(bucket_name)
        results['actions_taken'].extend(apply_uk_tags_result['actions'])
        results['errors'].extend(apply_uk_tags_result['errors'])
        
        # 5. Verify encryption is enabled
        verify_encryption_result = verify_bucket_encryption(bucket_name)
        results['actions_taken'].extend(verify_encryption_result['actions'])
        results['errors'].extend(verify_encryption_result['errors'])
        
        # Determine final compliance status
        if results['errors']:
            results['compliance_status'] = 'NON_COMPLIANT'
        
        logger.info(f"Remediation completed for bucket {bucket_name}. Actions: {len(results['actions_taken'])}, Errors: {len(results['errors'])}")
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        results['errors'].append(f"General remediation error: {str(e)}")
        results['compliance_status'] = 'NON_COMPLIANT'
    
    return results

def block_public_access(bucket_name: str) -> Dict[str, List[str]]:
    """Block all public access to the S3 bucket"""
    result = {'actions': [], 'errors': []}
    
    try:
        if DRY_RUN:
            result['actions'].append(f"DRY RUN: Would block public access for bucket {bucket_name}")
            return result
        
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        result['actions'].append(f"Blocked public access for bucket {bucket_name}")
        logger.info(f"Successfully blocked public access for bucket {bucket_name}")
        
    except ClientError as e:
        error_msg = f"Failed to block public access for bucket {bucket_name}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def remove_public_bucket_policy(bucket_name: str) -> Dict[str, List[str]]:
    """Remove or modify bucket policy to remove public access"""
    result = {'actions': [], 'errors': []}
    
    try:
        # Get current bucket policy
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                result['actions'].append(f"No bucket policy found for {bucket_name}")
                return result
            else:
                raise e
        
        # Check if policy has public access
        has_public_access = check_policy_for_public_access(policy)
        
        if has_public_access:
            if DRY_RUN:
                result['actions'].append(f"DRY RUN: Would remove public bucket policy for {bucket_name}")
                return result
            
            # Remove the entire policy for safety (can be refined to remove only public statements)
            s3_client.delete_bucket_policy(Bucket=bucket_name)
            result['actions'].append(f"Removed public bucket policy for {bucket_name}")
            logger.info(f"Successfully removed public bucket policy for {bucket_name}")
        else:
            result['actions'].append(f"No public access found in bucket policy for {bucket_name}")
        
    except ClientError as e:
        error_msg = f"Failed to process bucket policy for {bucket_name}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def check_policy_for_public_access(policy: Dict[str, Any]) -> bool:
    """Check if bucket policy allows public access"""
    try:
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                
                # Check for wildcard principals
                if principal == '*' or principal == {'AWS': '*'}:
                    return True
                
                # Check for public principals in various formats
                if isinstance(principal, dict):
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    if '*' in aws_principals:
                        return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking policy for public access: {str(e)}")
        return True  # Assume public access if we can't parse

def remove_public_acls(bucket_name: str) -> Dict[str, List[str]]:
    """Remove public ACLs from bucket and objects"""
    result = {'actions': [], 'errors': []}
    
    try:
        # Get current bucket ACL
        acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = acl_response.get('Grants', [])
        
        has_public_acl = any(
            grant.get('Grantee', {}).get('URI') in [
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            ]
            for grant in grants
        )
        
        if has_public_acl:
            if DRY_RUN:
                result['actions'].append(f"DRY RUN: Would remove public ACLs for bucket {bucket_name}")
                return result
            
            # Set private ACL
            s3_client.put_bucket_acl(Bucket=bucket_name, ACL='private')
            result['actions'].append(f"Removed public ACLs for bucket {bucket_name}")
            logger.info(f"Successfully removed public ACLs for bucket {bucket_name}")
        else:
            result['actions'].append(f"No public ACLs found for bucket {bucket_name}")
        
    except ClientError as e:
        error_msg = f"Failed to process ACLs for bucket {bucket_name}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def apply_uk_compliance_tags(bucket_name: str) -> Dict[str, List[str]]:
    """Apply compliance tags to the bucket"""
    result = {'actions': [], 'errors': []}
    
    if not UK_COMPLIANCE_MODE:
        return result
    
    try:
        # Get current tags
        try:
            current_tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            current_tags = {tag['Key']: tag['Value'] for tag in current_tags_response.get('TagSet', [])}
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchTagSet':
                current_tags = {}
            else:
                raise e
        
        # Define required compliance tags
        required_tags = {
            'DataClassification': 'internal',
            'Environment': 'production',
            'CostCenter': 'security',
            'Owner': 'security-team',
            'Project': 'uk-landing-zone',
            'ComplianceFramework': 'Security Standards,UK-GDPR',
            'AutoRemediated': 'true',
            'RemediationDate': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        # Merge with existing tags (don't overwrite existing values)
        updated_tags = current_tags.copy()
        tags_added = []
        
        for key, value in required_tags.items():
            if key not in updated_tags:
                updated_tags[key] = value
                tags_added.append(key)
        
        if tags_added:
            if DRY_RUN:
                result['actions'].append(f"DRY RUN: Would add compliance tags to bucket {bucket_name}: {tags_added}")
                return result
            
            # Convert to TagSet format
            tag_set = [{'Key': k, 'Value': v} for k, v in updated_tags.items()]
            
            s3_client.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={'TagSet': tag_set}
            )
            result['actions'].append(f"Added compliance tags to bucket {bucket_name}: {tags_added}")
            logger.info(f"Successfully added compliance tags to bucket {bucket_name}")
        else:
            result['actions'].append(f"All required compliance tags already present for bucket {bucket_name}")
        
    except ClientError as e:
        error_msg = f"Failed to apply compliance tags to bucket {bucket_name}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def verify_bucket_encryption(bucket_name: str) -> Dict[str, List[str]]:
    """Verify that bucket encryption is enabled"""
    result = {'actions': [], 'errors': []}
    
    try:
        # Check bucket encryption
        try:
            encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
            result['actions'].append(f"Bucket {bucket_name} has encryption enabled")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                # Encryption not configured - this is a separate issue that should be handled
                # by a different remediation function, but we'll note it
                result['errors'].append(f"Bucket {bucket_name} does not have encryption enabled - requires separate remediation")
                logger.warning(f"Bucket {bucket_name} does not have encryption enabled")
            else:
                raise e
        
    except ClientError as e:
        error_msg = f"Failed to verify encryption for bucket {bucket_name}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def send_notification(bucket_name: str, results: Dict[str, Any]) -> None:
    """Send SNS notification about remediation results"""
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return
        
        message = {
            'event_type': 'S3_PUBLIC_ACCESS_REMEDIATION',
            'bucket_name': bucket_name,
            'compliance_status': results['compliance_status'],
            'actions_taken': results['actions_taken'],
            'errors': results['errors'],
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown',
            'dry_run': DRY_RUN
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"S3 Public Access Remediation - {bucket_name}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent notification for bucket {bucket_name}")
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")

def send_error_notification(error_message: str) -> None:
    """Send error notification"""
    try:
        if not SNS_TOPIC_ARN:
            return
        
        message = {
            'event_type': 'S3_PUBLIC_ACCESS_REMEDIATION_ERROR',
            'error_message': error_message,
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="S3 Public Access Remediation Error",
            Message=json.dumps(message, indent=2)
        )
        
    except Exception as e:
        logger.error(f"Failed to send error notification: {str(e)}")

def update_security_hub_finding(event: Dict[str, Any], results: Dict[str, Any]) -> None:
    """Update Security Hub finding with remediation results"""
    try:
        if 'findings' not in event:
            return
        
        for finding in event['findings']:
            finding_id = finding.get('Id')
            product_arn = finding.get('ProductArn')
            
            if finding_id and product_arn:
                # Update finding with remediation note
                note_text = f"Automated remediation completed. Status: {results['compliance_status']}. Actions: {len(results['actions_taken'])}"
                
                securityhub_client.batch_update_findings(
                    FindingIdentifiers=[
                        {
                            'Id': finding_id,
                            'ProductArn': product_arn
                        }
                    ],
                    Note={
                        'Text': note_text,
                        'UpdatedBy': 'UK-Security-Automation'
                    },
                    Workflow={
                        'Status': 'RESOLVED' if results['compliance_status'] == 'COMPLIANT' else 'NEW'
                    }
                )
                
                logger.info(f"Updated Security Hub finding {finding_id}")
        
    except Exception as e:
        logger.error(f"Failed to update Security Hub finding: {str(e)}")

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