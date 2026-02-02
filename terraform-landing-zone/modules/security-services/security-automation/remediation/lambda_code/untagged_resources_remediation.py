#!/usr/bin/env python3
"""
Untagged Resources Remediation Lambda Function
Automatically applies compliance tags to untagged resources
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
resourcegroupstaggingapi_client = boto3.client('resourcegroupstaggingapi')
ec2_client = boto3.client('ec2')
s3_client = boto3.client('s3')
rds_client = boto3.client('rds')
lambda_client = boto3.client('lambda')
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')
securityhub_client = boto3.client('securityhub')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_BUCKET = os.environ.get('REMEDIATION_BUCKET')
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'
UK_COMPLIANCE_MODE = os.environ.get('UK_COMPLIANCE_MODE', 'true').lower() == 'true'
MANDATORY_TAGS = json.loads(os.environ.get('MANDATORY_TAGS', '["DataClassification", "Environment", "CostCenter", "Owner", "Project"]'))
DEFAULT_TAGS = json.loads(os.environ.get('DEFAULT_TAGS', '{}'))

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for untagged resources remediation
    
    Args:
        event: Lambda event containing resource information
        context: Lambda context object
        
    Returns:
        Dict containing remediation results
    """
    try:
        logger.info(f"Starting untagged resources remediation. Event: {json.dumps(event)}")
        
        # Extract resource information from event
        resource_arn = extract_resource_arn(event)
        if not resource_arn:
            logger.error("No resource ARN found in event")
            return create_response(False, "No resource ARN found in event")
        
        logger.info(f"Processing resource: {resource_arn}")
        
        # Check if resource is in specified regions
        if not validate_resource_location(resource_arn):
            logger.error(f"Resource {resource_arn} is not in specified regions")
            return create_response(False, f"Resource {resource_arn} is not in specified regions")
        
        # Perform remediation
        remediation_results = remediate_untagged_resource(resource_arn)
        
        # Send notification
        send_notification(resource_arn, remediation_results)
        
        # Update Security Hub finding if applicable
        update_security_hub_finding(event, remediation_results)
        
        logger.info("Untagged resource remediation completed successfully")
        return create_response(True, "Untagged resource remediation completed successfully", remediation_results)
        
    except Exception as e:
        logger.error(f"Untagged resource remediation failed: {str(e)}")
        send_error_notification(str(e))
        return create_response(False, f"Untagged resource remediation failed: {str(e)}")

def extract_resource_arn(event: Dict[str, Any]) -> Optional[str]:
    """Extract resource ARN from various event sources"""
    try:
        # Security Hub finding
        if 'findings' in event:
            for finding in event['findings']:
                if 'Resources' in finding:
                    for resource in finding['Resources']:
                        return resource.get('Id')
        
        # Config compliance event
        if 'resourceId' in event:
            # Convert resource ID to ARN based on resource type
            resource_type = event.get('resourceType', '')
            resource_id = event['resourceId']
            region = event.get('region', 'us-east-1')
            account_id = event.get('account', '')
            
            return construct_arn_from_resource_id(resource_type, resource_id, region, account_id)
        
        # Direct resource ARN
        if 'resource_arn' in event:
            return event['resource_arn']
            
        # GuardDuty finding
        if 'finding' in event and 'Service' in event['finding']:
            service = event['finding']['Service']
            if 'ResourceRole' in service and service['ResourceRole'] == 'TARGET':
                # Extract resource ARN from GuardDuty finding
                if 'InstanceDetails' in service:
                    instance_id = service['InstanceDetails'].get('InstanceId')
                    if instance_id:
                        region = event.get('region', 'us-east-1')
                        account_id = event.get('account', '')
                        return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
        
        return None
        
    except Exception as e:
        logger.error(f"Error extracting resource ARN: {str(e)}")
        return None

def construct_arn_from_resource_id(resource_type: str, resource_id: str, region: str, account_id: str) -> Optional[str]:
    """Construct ARN from resource type and ID"""
    try:
        arn_mappings = {
            'AWS::EC2::Instance': f"arn:aws:ec2:{region}:{account_id}:instance/{resource_id}",
            'AWS::EC2::Volume': f"arn:aws:ec2:{region}:{account_id}:volume/{resource_id}",
            'AWS::S3::Bucket': f"arn:aws:s3:::{resource_id}",
            'AWS::RDS::DBInstance': f"arn:aws:rds:{region}:{account_id}:db:{resource_id}",
            'AWS::Lambda::Function': f"arn:aws:lambda:{region}:{account_id}:function:{resource_id}",
            'AWS::IAM::Role': f"arn:aws:iam::{account_id}:role/{resource_id}",
            'AWS::IAM::User': f"arn:aws:iam::{account_id}:user/{resource_id}",
            'AWS::IAM::Policy': f"arn:aws:iam::{account_id}:policy/{resource_id}"
        }
        
        return arn_mappings.get(resource_type)
        
    except Exception as e:
        logger.error(f"Error constructing ARN: {str(e)}")
        return None

def validate_resource_location(resource_arn: str) -> bool:
    """Validate that resource is in specified regions"""
    try:
        # Parse ARN to extract region
        arn_parts = resource_arn.split(':')
        if len(arn_parts) < 6:
            return False
        
        region = arn_parts[3]
        
        # S3 buckets don't have region in ARN, need to check separately
        if 's3' in resource_arn:
            return validate_s3_bucket_location(arn_parts[5])
        
        # Check if in specified regions
        uk_regions = ['us-west-2', 'us-east-1']
        return region in uk_regions
        
    except Exception as e:
        logger.error(f"Error validating resource location: {str(e)}")
        return False

def validate_s3_bucket_location(bucket_name: str) -> bool:
    """Validate S3 bucket location"""
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
        logger.error(f"Error checking S3 bucket location: {str(e)}")
        return False

def remediate_untagged_resource(resource_arn: str) -> Dict[str, Any]:
    """
    Remediate untagged resource by applying compliance tags
    
    Args:
        resource_arn: ARN of the resource to remediate
        
    Returns:
        Dict containing remediation results
    """
    results = {
        'resource_arn': resource_arn,
        'actions_taken': [],
        'errors': [],
        'compliance_status': 'COMPLIANT'
    }
    
    try:
        # Get current tags for the resource
        current_tags = get_resource_tags(resource_arn)
        if current_tags is None:
            results['errors'].append(f"Could not retrieve tags for resource {resource_arn}")
            results['compliance_status'] = 'NON_COMPLIANT'
            return results
        
        # Determine missing mandatory tags
        missing_tags = get_missing_mandatory_tags(current_tags)
        
        if not missing_tags:
            results['actions_taken'].append(f"Resource {resource_arn} already has all mandatory compliance tags")
            return results
        
        # Apply missing tags
        apply_tags_result = apply_missing_tags(resource_arn, missing_tags)
        results['actions_taken'].extend(apply_tags_result['actions'])
        results['errors'].extend(apply_tags_result['errors'])
        
        # Validate UK data classification
        validate_classification_result = validate_uk_data_classification(resource_arn, current_tags, missing_tags)
        results['actions_taken'].extend(validate_classification_result['actions'])
        results['errors'].extend(validate_classification_result['errors'])
        
        # Determine final compliance status
        if results['errors']:
            results['compliance_status'] = 'NON_COMPLIANT'
        
        logger.info(f"Remediation completed for resource {resource_arn}. Actions: {len(results['actions_taken'])}, Errors: {len(results['errors'])}")
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        results['errors'].append(f"General remediation error: {str(e)}")
        results['compliance_status'] = 'NON_COMPLIANT'
    
    return results

def get_resource_tags(resource_arn: str) -> Optional[Dict[str, str]]:
    """Get current tags for a resource"""
    try:
        response = resourcegroupstaggingapi_client.get_resources(
            ResourceARNList=[resource_arn]
        )
        
        if response['ResourceTagMappingList']:
            resource = response['ResourceTagMappingList'][0]
            return {tag['Key']: tag['Value'] for tag in resource.get('Tags', [])}
        
        return {}
        
    except ClientError as e:
        logger.error(f"Error getting resource tags: {str(e)}")
        return None

def get_missing_mandatory_tags(current_tags: Dict[str, str]) -> Dict[str, str]:
    """Determine which mandatory tags are missing"""
    missing_tags = {}
    
    for tag_key in MANDATORY_TAGS:
        if tag_key not in current_tags:
            # Use default value if available, otherwise use a sensible default
            if tag_key in DEFAULT_TAGS:
                missing_tags[tag_key] = DEFAULT_TAGS[tag_key]
            else:
                # Provide region-specific defaults
                uk_defaults = {
                    'DataClassification': 'internal',
                    'Environment': 'production',
                    'CostCenter': 'unassigned',
                    'Owner': 'security-team',
                    'Project': 'uk-landing-zone',
                    'ComplianceFramework': 'Security Standards,UK-GDPR',
                    'AutoRemediated': 'true'
                }
                missing_tags[tag_key] = uk_defaults.get(tag_key, 'unknown')
    
    return missing_tags

def apply_missing_tags(resource_arn: str, missing_tags: Dict[str, str]) -> Dict[str, List[str]]:
    """Apply missing tags to the resource"""
    result = {'actions': [], 'errors': []}
    
    if not missing_tags:
        return result
    
    try:
        if DRY_RUN:
            tag_keys = list(missing_tags.keys())
            result['actions'].append(f"DRY RUN: Would apply missing tags to {resource_arn}: {tag_keys}")
            return result
        
        # Use Resource Groups Tagging API for most resources
        try:
            resourcegroupstaggingapi_client.tag_resources(
                ResourceARNList=[resource_arn],
                Tags=missing_tags
            )
            
            tag_keys = list(missing_tags.keys())
            result['actions'].append(f"Applied missing compliance tags to {resource_arn}: {tag_keys}")
            logger.info(f"Successfully applied tags to {resource_arn}")
            
        except ClientError as e:
            # Some resources might need service-specific tagging
            if 'InvalidParameterException' in str(e) or 'UnsupportedResourceType' in str(e):
                service_specific_result = apply_service_specific_tags(resource_arn, missing_tags)
                result['actions'].extend(service_specific_result['actions'])
                result['errors'].extend(service_specific_result['errors'])
            else:
                raise e
        
    except ClientError as e:
        error_msg = f"Failed to apply tags to {resource_arn}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def apply_service_specific_tags(resource_arn: str, tags: Dict[str, str]) -> Dict[str, List[str]]:
    """Apply tags using service-specific APIs"""
    result = {'actions': [], 'errors': []}
    
    try:
        # Parse ARN to determine service
        arn_parts = resource_arn.split(':')
        service = arn_parts[2]
        resource_id = arn_parts[5] if len(arn_parts) > 5 else arn_parts[4]
        
        if service == 's3':
            # S3 bucket tagging
            bucket_name = resource_id
            
            # Get existing tags
            try:
                existing_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                existing_tags = {tag['Key']: tag['Value'] for tag in existing_response.get('TagSet', [])}
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchTagSet':
                    existing_tags = {}
                else:
                    raise e
            
            # Merge tags
            merged_tags = existing_tags.copy()
            merged_tags.update(tags)
            
            # Apply tags
            tag_set = [{'Key': k, 'Value': v} for k, v in merged_tags.items()]
            s3_client.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={'TagSet': tag_set}
            )
            
            result['actions'].append(f"Applied S3-specific tags to bucket {bucket_name}")
            
        elif service == 'ec2':
            # EC2 resource tagging
            resource_type = arn_parts[5].split('/')[0]
            resource_id = arn_parts[5].split('/')[1]
            
            tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
            ec2_client.create_tags(
                Resources=[resource_id],
                Tags=tag_list
            )
            
            result['actions'].append(f"Applied EC2-specific tags to {resource_type} {resource_id}")
            
        elif service == 'rds':
            # RDS resource tagging
            rds_client.add_tags_to_resource(
                ResourceName=resource_arn,
                Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
            )
            
            result['actions'].append(f"Applied RDS-specific tags to {resource_arn}")
            
        elif service == 'lambda':
            # Lambda function tagging
            function_name = resource_id
            lambda_client.tag_resource(
                Resource=resource_arn,
                Tags=tags
            )
            
            result['actions'].append(f"Applied Lambda-specific tags to function {function_name}")
            
        elif service == 'iam':
            # IAM resource tagging
            resource_type = arn_parts[5].split('/')[0]
            resource_name = arn_parts[5].split('/')[1]
            
            tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
            
            if resource_type == 'role':
                iam_client.tag_role(RoleName=resource_name, Tags=tag_list)
            elif resource_type == 'user':
                iam_client.tag_user(UserName=resource_name, Tags=tag_list)
            elif resource_type == 'policy':
                iam_client.tag_policy(PolicyArn=resource_arn, Tags=tag_list)
            
            result['actions'].append(f"Applied IAM-specific tags to {resource_type} {resource_name}")
            
        else:
            result['errors'].append(f"Service-specific tagging not implemented for service: {service}")
        
    except ClientError as e:
        error_msg = f"Failed to apply service-specific tags to {resource_arn}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def validate_uk_data_classification(resource_arn: str, current_tags: Dict[str, str], applied_tags: Dict[str, str]) -> Dict[str, List[str]]:
    """Validate UK data classification compliance"""
    result = {'actions': [], 'errors': []}
    
    if not UK_COMPLIANCE_MODE:
        return result
    
    try:
        # Get the data classification (from current tags or newly applied)
        data_classification = current_tags.get('DataClassification') or applied_tags.get('DataClassification')
        
        if not data_classification:
            result['errors'].append(f"No DataClassification tag found for {resource_arn}")
            return result
        
        # Validate classification value
        valid_classifications = ['public', 'internal', 'confidential', 'restricted']
        if data_classification.lower() not in valid_classifications:
            result['errors'].append(f"Invalid DataClassification value '{data_classification}' for {resource_arn}. Must be one of: {valid_classifications}")
            return result
        
        # Check if resource type is appropriate for classification level
        classification_validation = validate_resource_classification_compatibility(resource_arn, data_classification)
        result['actions'].extend(classification_validation['actions'])
        result['errors'].extend(classification_validation['errors'])
        
        result['actions'].append(f"Validated UK data classification '{data_classification}' for {resource_arn}")
        
    except Exception as e:
        error_msg = f"Error validating UK data classification: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def validate_resource_classification_compatibility(resource_arn: str, classification: str) -> Dict[str, List[str]]:
    """Validate that resource type is compatible with data classification"""
    result = {'actions': [], 'errors': []}
    
    try:
        # Parse ARN to get service and resource type
        arn_parts = resource_arn.split(':')
        service = arn_parts[2]
        
        # Define classification requirements
        high_security_classifications = ['confidential', 'restricted']
        
        if classification.lower() in high_security_classifications:
            # Check service-specific requirements for high-security data
            if service == 's3':
                # S3 buckets with confidential/restricted data should have encryption
                bucket_name = arn_parts[5]
                if not check_s3_encryption(bucket_name):
                    result['errors'].append(f"S3 bucket {bucket_name} with {classification} data must have encryption enabled")
            
            elif service == 'ec2':
                # EC2 volumes with confidential/restricted data should be encrypted
                if 'volume' in resource_arn:
                    volume_id = arn_parts[5].split('/')[1]
                    if not check_ebs_encryption(volume_id):
                        result['errors'].append(f"EBS volume {volume_id} with {classification} data must be encrypted")
            
            elif service == 'rds':
                # RDS instances with confidential/restricted data should be encrypted
                if not check_rds_encryption(resource_arn):
                    result['errors'].append(f"RDS instance with {classification} data must have encryption enabled")
        
        result['actions'].append(f"Validated resource classification compatibility for {resource_arn}")
        
    except Exception as e:
        error_msg = f"Error validating resource classification compatibility: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def check_s3_encryption(bucket_name: str) -> bool:
    """Check if S3 bucket has encryption enabled"""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        raise e

def check_ebs_encryption(volume_id: str) -> bool:
    """Check if EBS volume is encrypted"""
    try:
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        if response['Volumes']:
            return response['Volumes'][0].get('Encrypted', False)
        return False
    except ClientError:
        return False

def check_rds_encryption(resource_arn: str) -> bool:
    """Check if RDS instance has encryption enabled"""
    try:
        # Extract DB instance identifier from ARN
        db_instance_id = resource_arn.split(':')[-1]
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        
        if response['DBInstances']:
            return response['DBInstances'][0].get('StorageEncrypted', False)
        return False
    except ClientError:
        return False

def send_notification(resource_arn: str, results: Dict[str, Any]) -> None:
    """Send SNS notification about remediation results"""
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return
        
        message = {
            'event_type': 'UNTAGGED_RESOURCE_REMEDIATION',
            'resource_arn': resource_arn,
            'compliance_status': results['compliance_status'],
            'actions_taken': results['actions_taken'],
            'errors': results['errors'],
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown',
            'dry_run': DRY_RUN
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Untagged Resource Remediation - {resource_arn.split('/')[-1]}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent notification for resource {resource_arn}")
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")

def send_error_notification(error_message: str) -> None:
    """Send error notification"""
    try:
        if not SNS_TOPIC_ARN:
            return
        
        message = {
            'event_type': 'UNTAGGED_RESOURCE_REMEDIATION_ERROR',
            'error_message': error_message,
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Untagged Resource Remediation Error",
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
                note_text = f"Automated compliance tagging completed. Status: {results['compliance_status']}. Actions: {len(results['actions_taken'])}"
                
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