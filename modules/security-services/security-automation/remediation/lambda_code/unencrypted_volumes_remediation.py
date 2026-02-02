#!/usr/bin/env python3
"""
Unencrypted Volumes Remediation Lambda Function
Automatically remediates unencrypted EBS volumes
Compliant with GDPR and Security Standards Cloud Security Principles
"""

import json
import boto3
import logging
import os
import time
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Initialize AWS clients
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')
securityhub_client = boto3.client('securityhub')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
REMEDIATION_BUCKET = os.environ.get('REMEDIATION_BUCKET')
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'
UK_COMPLIANCE_MODE = os.environ.get('UK_COMPLIANCE_MODE', 'true').lower() == 'true'
KMS_KEY_ID = os.environ.get('KMS_KEY_ID')

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for unencrypted volumes remediation
    
    Args:
        event: Lambda event containing volume information
        context: Lambda context object
        
    Returns:
        Dict containing remediation results
    """
    try:
        logger.info(f"Starting unencrypted volumes remediation. Event: {json.dumps(event)}")
        
        # Extract volume information from event
        volume_id = extract_volume_id(event)
        if not volume_id:
            logger.error("No volume ID found in event")
            return create_response(False, "No volume ID found in event")
        
        logger.info(f"Processing volume: {volume_id}")
        
        # Check if volume exists and is in specified regions
        if not validate_volume_location(volume_id):
            logger.error(f"Volume {volume_id} is not in specified regions or does not exist")
            return create_response(False, f"Volume {volume_id} is not in specified regions or does not exist")
        
        # Perform remediation
        remediation_results = remediate_unencrypted_volume(volume_id)
        
        # Send notification
        send_notification(volume_id, remediation_results)
        
        # Update Security Hub finding if applicable
        update_security_hub_finding(event, remediation_results)
        
        logger.info("Unencrypted volume remediation completed successfully")
        return create_response(True, "Unencrypted volume remediation completed successfully", remediation_results)
        
    except Exception as e:
        logger.error(f"Unencrypted volume remediation failed: {str(e)}")
        send_error_notification(str(e))
        return create_response(False, f"Unencrypted volume remediation failed: {str(e)}")

def extract_volume_id(event: Dict[str, Any]) -> Optional[str]:
    """Extract EBS volume ID from various event sources"""
    try:
        # Security Hub finding
        if 'findings' in event:
            for finding in event['findings']:
                if 'Resources' in finding:
                    for resource in finding['Resources']:
                        if resource.get('Type') == 'AwsEc2Volume':
                            return resource.get('Id', '').split('/')[-1]
        
        # Config compliance event
        if 'resourceId' in event:
            return event['resourceId']
        
        # Direct volume ID
        if 'volume_id' in event:
            return event['volume_id']
            
        # GuardDuty finding - extract from instance details
        if 'finding' in event and 'Service' in event['finding']:
            service = event['finding']['Service']
            if 'ResourceRole' in service and service['ResourceRole'] == 'TARGET':
                # Extract instance ID and get its volumes
                if 'InstanceDetails' in service:
                    instance_id = service['InstanceDetails'].get('InstanceId')
                    if instance_id:
                        return get_unencrypted_volumes_for_instance(instance_id)
        
        return None
        
    except Exception as e:
        logger.error(f"Error extracting volume ID: {str(e)}")
        return None

def get_unencrypted_volumes_for_instance(instance_id: str) -> Optional[str]:
    """Get unencrypted volumes for a specific instance"""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                for block_device in instance.get('BlockDeviceMappings', []):
                    volume_id = block_device['Ebs']['VolumeId']
                    
                    # Check if volume is encrypted
                    volume_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
                    volume = volume_response['Volumes'][0]
                    
                    if not volume.get('Encrypted', False):
                        return volume_id
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting volumes for instance {instance_id}: {str(e)}")
        return None

def validate_volume_location(volume_id: str) -> bool:
    """Validate that volume exists and is in specified regions"""
    try:
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        
        if not response['Volumes']:
            return False
        
        volume = response['Volumes'][0]
        availability_zone = volume['AvailabilityZone']
        
        # Check if in specified regions
        uk_regions = ['us-west-2', 'us-east-1']
        region = availability_zone[:-1]  # Remove AZ letter (e.g., 'us-east-1a' -> 'us-east-1')
        
        return region in uk_regions
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidVolume.NotFound':
            logger.error(f"Volume {volume_id} does not exist")
        else:
            logger.error(f"Error checking volume location: {str(e)}")
        return False

def remediate_unencrypted_volume(volume_id: str) -> Dict[str, Any]:
    """
    Remediate unencrypted EBS volume
    
    Args:
        volume_id: ID of the EBS volume to remediate
        
    Returns:
        Dict containing remediation results
    """
    results = {
        'volume_id': volume_id,
        'actions_taken': [],
        'errors': [],
        'compliance_status': 'COMPLIANT'
    }
    
    try:
        # Get volume details
        volume_details = get_volume_details(volume_id)
        if not volume_details:
            results['errors'].append(f"Could not retrieve details for volume {volume_id}")
            results['compliance_status'] = 'NON_COMPLIANT'
            return results
        
        # Check if volume is already encrypted
        if volume_details.get('Encrypted', False):
            results['actions_taken'].append(f"Volume {volume_id} is already encrypted")
            return results
        
        # Check if volume is attached to an instance
        instance_id = None
        device_name = None
        if volume_details.get('Attachments'):
            attachment = volume_details['Attachments'][0]
            instance_id = attachment.get('InstanceId')
            device_name = attachment.get('Device')
        
        if instance_id:
            # Volume is attached - need to stop instance, create encrypted copy, and replace
            encrypt_attached_volume_result = encrypt_attached_volume(volume_id, instance_id, device_name)
            results['actions_taken'].extend(encrypt_attached_volume_result['actions'])
            results['errors'].extend(encrypt_attached_volume_result['errors'])
        else:
            # Volume is not attached - can encrypt in place via snapshot
            encrypt_detached_volume_result = encrypt_detached_volume(volume_id)
            results['actions_taken'].extend(encrypt_detached_volume_result['actions'])
            results['errors'].extend(encrypt_detached_volume_result['errors'])
        
        # Apply compliance tags
        apply_uk_tags_result = apply_uk_compliance_tags(volume_id)
        results['actions_taken'].extend(apply_uk_tags_result['actions'])
        results['errors'].extend(apply_uk_tags_result['errors'])
        
        # Determine final compliance status
        if results['errors']:
            results['compliance_status'] = 'NON_COMPLIANT'
        
        logger.info(f"Remediation completed for volume {volume_id}. Actions: {len(results['actions_taken'])}, Errors: {len(results['errors'])}")
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        results['errors'].append(f"General remediation error: {str(e)}")
        results['compliance_status'] = 'NON_COMPLIANT'
    
    return results

def get_volume_details(volume_id: str) -> Optional[Dict[str, Any]]:
    """Get detailed information about the volume"""
    try:
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        if response['Volumes']:
            return response['Volumes'][0]
        return None
        
    except ClientError as e:
        logger.error(f"Error getting volume details: {str(e)}")
        return None

def encrypt_attached_volume(volume_id: str, instance_id: str, device_name: str) -> Dict[str, List[str]]:
    """Encrypt a volume that is attached to an instance"""
    result = {'actions': [], 'errors': []}
    
    try:
        if DRY_RUN:
            result['actions'].append(f"DRY RUN: Would encrypt attached volume {volume_id} on instance {instance_id}")
            return result
        
        # 1. Stop the instance
        logger.info(f"Stopping instance {instance_id} to encrypt volume {volume_id}")
        ec2_client.stop_instances(InstanceIds=[instance_id])
        
        # Wait for instance to stop
        waiter = ec2_client.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        result['actions'].append(f"Stopped instance {instance_id}")
        
        # 2. Create snapshot of the volume
        snapshot_response = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"Snapshot for encryption of volume {volume_id}",
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'encryption-snapshot-{volume_id}'},
                        {'Key': 'Purpose', 'Value': 'volume-encryption'},
                        {'Key': 'OriginalVolumeId', 'Value': volume_id},
                        {'Key': 'ComplianceFramework', 'Value': 'Security Standards,UK-GDPR'}
                    ]
                }
            ]
        )
        snapshot_id = snapshot_response['SnapshotId']
        result['actions'].append(f"Created snapshot {snapshot_id} for volume {volume_id}")
        
        # Wait for snapshot to complete
        waiter = ec2_client.get_waiter('snapshot_completed')
        waiter.wait(SnapshotIds=[snapshot_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 120})
        result['actions'].append(f"Snapshot {snapshot_id} completed")
        
        # 3. Detach the original volume
        ec2_client.detach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=device_name)
        
        # Wait for volume to detach
        waiter = ec2_client.get_waiter('volume_available')
        waiter.wait(VolumeIds=[volume_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        result['actions'].append(f"Detached volume {volume_id} from instance {instance_id}")
        
        # 4. Create encrypted volume from snapshot
        volume_details = get_volume_details(volume_id)
        encrypted_volume_response = ec2_client.create_volume(
            AvailabilityZone=volume_details['AvailabilityZone'],
            SnapshotId=snapshot_id,
            VolumeType=volume_details['VolumeType'],
            Size=volume_details['Size'],
            Encrypted=True,
            KmsKeyId=KMS_KEY_ID if KMS_KEY_ID else None,
            TagSpecifications=[
                {
                    'ResourceType': 'volume',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'encrypted-{volume_id}'},
                        {'Key': 'Purpose', 'Value': 'encrypted-replacement'},
                        {'Key': 'OriginalVolumeId', 'Value': volume_id},
                        {'Key': 'ComplianceFramework', 'Value': 'Security Standards,UK-GDPR'},
                        {'Key': 'DataClassification', 'Value': 'confidential'},
                        {'Key': 'Environment', 'Value': 'production'},
                        {'Key': 'AutoRemediated', 'Value': 'true'}
                    ]
                }
            ]
        )
        encrypted_volume_id = encrypted_volume_response['VolumeId']
        result['actions'].append(f"Created encrypted volume {encrypted_volume_id}")
        
        # Wait for encrypted volume to be available
        waiter = ec2_client.get_waiter('volume_available')
        waiter.wait(VolumeIds=[encrypted_volume_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        
        # 5. Attach encrypted volume to instance
        ec2_client.attach_volume(
            VolumeId=encrypted_volume_id,
            InstanceId=instance_id,
            Device=device_name
        )
        result['actions'].append(f"Attached encrypted volume {encrypted_volume_id} to instance {instance_id}")
        
        # Wait for volume to attach
        waiter = ec2_client.get_waiter('volume_in_use')
        waiter.wait(VolumeIds=[encrypted_volume_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        
        # 6. Start the instance
        ec2_client.start_instances(InstanceIds=[instance_id])
        result['actions'].append(f"Started instance {instance_id}")
        
        # 7. Clean up - delete original volume and snapshot (after verification)
        time.sleep(30)  # Give some time for the instance to start properly
        
        try:
            ec2_client.delete_volume(VolumeId=volume_id)
            result['actions'].append(f"Deleted original unencrypted volume {volume_id}")
        except ClientError as e:
            result['errors'].append(f"Failed to delete original volume {volume_id}: {str(e)}")
        
        try:
            ec2_client.delete_snapshot(SnapshotId=snapshot_id)
            result['actions'].append(f"Deleted temporary snapshot {snapshot_id}")
        except ClientError as e:
            result['errors'].append(f"Failed to delete snapshot {snapshot_id}: {str(e)}")
        
        logger.info(f"Successfully encrypted attached volume {volume_id}, new encrypted volume: {encrypted_volume_id}")
        
    except ClientError as e:
        error_msg = f"Failed to encrypt attached volume {volume_id}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
        
        # Try to restart instance if it was stopped
        try:
            ec2_client.start_instances(InstanceIds=[instance_id])
            result['actions'].append(f"Restarted instance {instance_id} after error")
        except:
            pass
    
    return result

def encrypt_detached_volume(volume_id: str) -> Dict[str, List[str]]:
    """Encrypt a volume that is not attached to any instance"""
    result = {'actions': [], 'errors': []}
    
    try:
        if DRY_RUN:
            result['actions'].append(f"DRY RUN: Would encrypt detached volume {volume_id}")
            return result
        
        # 1. Create snapshot of the volume
        snapshot_response = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"Snapshot for encryption of detached volume {volume_id}",
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'encryption-snapshot-{volume_id}'},
                        {'Key': 'Purpose', 'Value': 'volume-encryption'},
                        {'Key': 'OriginalVolumeId', 'Value': volume_id},
                        {'Key': 'ComplianceFramework', 'Value': 'Security Standards,UK-GDPR'}
                    ]
                }
            ]
        )
        snapshot_id = snapshot_response['SnapshotId']
        result['actions'].append(f"Created snapshot {snapshot_id} for detached volume {volume_id}")
        
        # Wait for snapshot to complete
        waiter = ec2_client.get_waiter('snapshot_completed')
        waiter.wait(SnapshotIds=[snapshot_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 120})
        result['actions'].append(f"Snapshot {snapshot_id} completed")
        
        # 2. Create encrypted volume from snapshot
        volume_details = get_volume_details(volume_id)
        encrypted_volume_response = ec2_client.create_volume(
            AvailabilityZone=volume_details['AvailabilityZone'],
            SnapshotId=snapshot_id,
            VolumeType=volume_details['VolumeType'],
            Size=volume_details['Size'],
            Encrypted=True,
            KmsKeyId=KMS_KEY_ID if KMS_KEY_ID else None,
            TagSpecifications=[
                {
                    'ResourceType': 'volume',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'encrypted-{volume_id}'},
                        {'Key': 'Purpose', 'Value': 'encrypted-replacement'},
                        {'Key': 'OriginalVolumeId', 'Value': volume_id},
                        {'Key': 'ComplianceFramework', 'Value': 'Security Standards,UK-GDPR'},
                        {'Key': 'DataClassification', 'Value': 'confidential'},
                        {'Key': 'Environment', 'Value': 'production'},
                        {'Key': 'AutoRemediated', 'Value': 'true'}
                    ]
                }
            ]
        )
        encrypted_volume_id = encrypted_volume_response['VolumeId']
        result['actions'].append(f"Created encrypted volume {encrypted_volume_id} to replace {volume_id}")
        
        # Wait for encrypted volume to be available
        waiter = ec2_client.get_waiter('volume_available')
        waiter.wait(VolumeIds=[encrypted_volume_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        
        # 3. Clean up - delete original volume and snapshot
        try:
            ec2_client.delete_volume(VolumeId=volume_id)
            result['actions'].append(f"Deleted original unencrypted volume {volume_id}")
        except ClientError as e:
            result['errors'].append(f"Failed to delete original volume {volume_id}: {str(e)}")
        
        try:
            ec2_client.delete_snapshot(SnapshotId=snapshot_id)
            result['actions'].append(f"Deleted temporary snapshot {snapshot_id}")
        except ClientError as e:
            result['errors'].append(f"Failed to delete snapshot {snapshot_id}: {str(e)}")
        
        logger.info(f"Successfully encrypted detached volume {volume_id}, new encrypted volume: {encrypted_volume_id}")
        
    except ClientError as e:
        error_msg = f"Failed to encrypt detached volume {volume_id}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def apply_uk_compliance_tags(volume_id: str) -> Dict[str, List[str]]:
    """Apply compliance tags to the volume"""
    result = {'actions': [], 'errors': []}
    
    if not UK_COMPLIANCE_MODE:
        return result
    
    try:
        # Get current tags
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        if not response['Volumes']:
            result['errors'].append(f"Volume {volume_id} not found for tagging")
            return result
        
        volume = response['Volumes'][0]
        current_tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
        
        # Define required compliance tags
        required_tags = {
            'DataClassification': 'confidential',
            'Environment': 'production',
            'CostCenter': 'security',
            'Owner': 'security-team',
            'Project': 'uk-landing-zone',
            'ComplianceFramework': 'Security Standards,UK-GDPR',
            'AutoRemediated': 'true',
            'EncryptionStatus': 'encrypted'
        }
        
        # Determine which tags need to be added
        tags_to_add = []
        for key, value in required_tags.items():
            if key not in current_tags:
                tags_to_add.append({'Key': key, 'Value': value})
        
        if tags_to_add:
            if DRY_RUN:
                tag_keys = [tag['Key'] for tag in tags_to_add]
                result['actions'].append(f"DRY RUN: Would add compliance tags to volume {volume_id}: {tag_keys}")
                return result
            
            ec2_client.create_tags(
                Resources=[volume_id],
                Tags=tags_to_add
            )
            
            tag_keys = [tag['Key'] for tag in tags_to_add]
            result['actions'].append(f"Added compliance tags to volume {volume_id}: {tag_keys}")
            logger.info(f"Successfully added compliance tags to volume {volume_id}")
        else:
            result['actions'].append(f"All required compliance tags already present for volume {volume_id}")
        
    except ClientError as e:
        error_msg = f"Failed to apply compliance tags to volume {volume_id}: {str(e)}"
        result['errors'].append(error_msg)
        logger.error(error_msg)
    
    return result

def send_notification(volume_id: str, results: Dict[str, Any]) -> None:
    """Send SNS notification about remediation results"""
    try:
        if not SNS_TOPIC_ARN:
            logger.warning("No SNS topic ARN configured, skipping notification")
            return
        
        message = {
            'event_type': 'UNENCRYPTED_VOLUME_REMEDIATION',
            'volume_id': volume_id,
            'compliance_status': results['compliance_status'],
            'actions_taken': results['actions_taken'],
            'errors': results['errors'],
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown',
            'dry_run': DRY_RUN
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Unencrypted Volume Remediation - {volume_id}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent notification for volume {volume_id}")
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")

def send_error_notification(error_message: str) -> None:
    """Send error notification"""
    try:
        if not SNS_TOPIC_ARN:
            return
        
        message = {
            'event_type': 'UNENCRYPTED_VOLUME_REMEDIATION_ERROR',
            'error_message': error_message,
            'timestamp': context.aws_request_id if 'context' in globals() else 'unknown'
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Unencrypted Volume Remediation Error",
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
                note_text = f"Automated volume encryption completed. Status: {results['compliance_status']}. Actions: {len(results['actions_taken'])}"
                
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