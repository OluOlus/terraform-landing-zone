#!/usr/bin/env python3
"""
Log Cleanup Lambda Function
Automated cleanup of expired logs based on retention policies
"""

import json
import boto3
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
logs_client = boto3.client('logs')
s3_client = boto3.client('s3')

# Environment variables
RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', '2555'))
DRY_RUN = os.environ.get('DRY_RUN', 'true').lower() == 'true'

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for log cleanup
    """
    logger.info(f"Starting log cleanup process. DRY_RUN: {DRY_RUN}")
    
    results = {
        'cloudwatch_logs_processed': 0,
        's3_objects_processed': 0,
        'errors': []
    }
    
    try:
        # Clean up CloudWatch Log Groups
        cloudwatch_results = cleanup_cloudwatch_logs()
        results['cloudwatch_logs_processed'] = cloudwatch_results['processed']
        results['errors'].extend(cloudwatch_results['errors'])
        
        # Clean up S3 Log Objects
        s3_results = cleanup_s3_logs()
        results['s3_objects_processed'] = s3_results['processed']
        results['errors'].extend(s3_results['errors'])
        
        logger.info(f"Log cleanup completed. Results: {results}")
        
    except Exception as e:
        logger.error(f"Error during log cleanup: {str(e)}")
        results['errors'].append(f"General error: {str(e)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(results)
    }

def cleanup_cloudwatch_logs() -> Dict[str, Any]:
    """
    Clean up expired CloudWatch log streams
    """
    results = {'processed': 0, 'errors': []}
    cutoff_time = datetime.now() - timedelta(days=RETENTION_DAYS)
    cutoff_timestamp = int(cutoff_time.timestamp() * 1000)
    
    try:
        # Get all log groups
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                log_group_name = log_group['logGroupName']
                
                try:
                    # Get log streams for this group
                    stream_paginator = logs_client.get_paginator('describe_log_streams')
                    
                    for stream_page in stream_paginator.paginate(
                        logGroupName=log_group_name,
                        orderBy='LastEventTime'
                    ):
                        for log_stream in stream_page['logStreams']:
                            last_event_time = log_stream.get('lastEventTime', 0)
                            
                            if last_event_time < cutoff_timestamp:
                                stream_name = log_stream['logStreamName']
                                
                                if DRY_RUN:
                                    logger.info(f"DRY RUN: Would delete log stream {stream_name} from {log_group_name}")
                                else:
                                    logs_client.delete_log_stream(
                                        logGroupName=log_group_name,
                                        logStreamName=stream_name
                                    )
                                    logger.info(f"Deleted log stream {stream_name} from {log_group_name}")
                                
                                results['processed'] += 1
                
                except Exception as e:
                    error_msg = f"Error processing log group {log_group_name}: {str(e)}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
    
    except Exception as e:
        error_msg = f"Error listing log groups: {str(e)}"
        logger.error(error_msg)
        results['errors'].append(error_msg)
    
    return results

def cleanup_s3_logs() -> Dict[str, Any]:
    """
    Clean up expired S3 log objects (beyond lifecycle policies)
    """
    results = {'processed': 0, 'errors': []}
    cutoff_time = datetime.now() - timedelta(days=RETENTION_DAYS)
    
    try:
        # Get all buckets
        response = s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            # Only process log buckets
            if 'log' not in bucket_name.lower():
                continue
            
            try:
                # List objects in the bucket
                paginator = s3_client.get_paginator('list_objects_v2')
                
                for page in paginator.paginate(Bucket=bucket_name):
                    if 'Contents' not in page:
                        continue
                    
                    for obj in page['Contents']:
                        if obj['LastModified'].replace(tzinfo=None) < cutoff_time:
                            object_key = obj['Key']
                            
                            if DRY_RUN:
                                logger.info(f"DRY RUN: Would delete S3 object s3://{bucket_name}/{object_key}")
                            else:
                                s3_client.delete_object(
                                    Bucket=bucket_name,
                                    Key=object_key
                                )
                                logger.info(f"Deleted S3 object s3://{bucket_name}/{object_key}")
                            
                            results['processed'] += 1
            
            except Exception as e:
                error_msg = f"Error processing S3 bucket {bucket_name}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
    
    except Exception as e:
        error_msg = f"Error listing S3 buckets: {str(e)}"
        logger.error(error_msg)
        results['errors'].append(error_msg)
    
    return results

def get_log_groups_by_prefix(prefix: str) -> List[str]:
    """
    Get log groups matching a specific prefix
    """
    log_groups = []
    
    try:
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate(logGroupNamePrefix=prefix):
            for log_group in page['logGroups']:
                log_groups.append(log_group['logGroupName'])
    
    except Exception as e:
        logger.error(f"Error getting log groups with prefix {prefix}: {str(e)}")
    
    return log_groups

def validate_retention_compliance(log_group_name: str) -> bool:
    """
    Validate that a log group meets retention requirements
    """
    try:
        response = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name
        )
        
        for log_group in response['logGroups']:
            if log_group['logGroupName'] == log_group_name:
                retention_days = log_group.get('retentionInDays')
                
                if retention_days is None:
                    logger.warning(f"Log group {log_group_name} has no retention policy")
                    return False
                
                if retention_days < RETENTION_DAYS:
                    logger.warning(f"Log group {log_group_name} retention ({retention_days} days) is less than required ({RETENTION_DAYS} days)")
                    return False
                
                return True
    
    except Exception as e:
        logger.error(f"Error validating retention for {log_group_name}: {str(e)}")
        return False
    
    return False