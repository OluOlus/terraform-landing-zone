# Disaster Recovery Runbook

## Overview

This runbook provides procedures for disaster recovery scenarios in the AWS Secure Landing Zone, including account recovery, data restoration, and service continuity.

## Recovery Objectives

- **RTO (Recovery Time Objective)**: 4 hours for critical services
- **RPO (Recovery Point Objective)**: 1 hour for critical data
- **RTO for Non-Critical**: 24 hours
- **RPO for Non-Critical**: 24 hours

## Disaster Scenarios

### 1. Account Compromise

#### Immediate Actions (0-30 minutes)

1. **Activate Break-Glass Access**
   ```bash
   # Use emergency access credentials
   aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/BreakGlassRole \
     --role-session-name emergency-response
   ```

2. **Assess Damage**
   ```bash
   # Check for unauthorized changes
   aws configservice get-compliance-details-by-config-rule \
     --config-rule-name required-tags
   
   # Review recent API calls
   aws logs filter-log-events --log-group-name CloudTrail/ManagementEvents \
     --start-time $(date -d '24 hours ago' +%s)000
   ```

3. **Isolate Affected Resources**
   ```bash
   # Create isolation security group
   aws ec2 create-security-group --group-name emergency-isolation \
     --description "Emergency isolation group"
   
   # Apply to compromised instances
   aws ec2 modify-instance-attribute --instance-id <instance-id> \
     --groups sg-emergency-isolation
   ```

#### Recovery Actions (30 minutes - 4 hours)

1. **Restore from Backup**
   ```bash
   # List available backups
   aws backup list-recovery-points --backup-vault-name default
   
   # Restore critical databases
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier restored-production-db \
     --db-snapshot-identifier automated-snapshot-latest
   ```

2. **Rebuild Infrastructure**
   ```bash
   # Deploy clean environment
   cd environments/production
   terraform init
   terraform plan -var="emergency_mode=true"
   terraform apply -auto-approve
   ```

### 2. Regional Outage

#### Immediate Actions (0-15 minutes)

1. **Activate Secondary Region**
   ```bash
   # Switch to backup region
   export AWS_DEFAULT_REGION=us-west-2
   
   # Check service availability
   aws ec2 describe-availability-zones --region us-west-2
   ```

2. **DNS Failover**
   ```bash
   # Update Route 53 records
   aws route53 change-resource-record-sets \
     --hosted-zone-id Z123456789 \
     --change-batch file://failover-changeset.json
   ```

#### Recovery Actions (15 minutes - 2 hours)

1. **Restore Services in Secondary Region**
   ```bash
   # Deploy infrastructure
   cd environments/production-dr
   terraform init -backend-config="region=us-west-2"
   terraform apply -auto-approve
   ```

2. **Data Synchronization**
   ```bash
   # Restore from cross-region backups
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier production-db-dr \
     --db-snapshot-identifier cross-region-snapshot \
     --region us-west-2
   ```

### 3. Data Loss Event

#### Immediate Actions (0-30 minutes)

1. **Stop All Write Operations**
   ```bash
   # Enable read-only mode
   aws rds modify-db-instance --db-instance-identifier production-db \
     --backup-retention-period 35 --apply-immediately
   ```

2. **Assess Data Loss Scope**
   ```bash
   # Check backup status
   aws backup list-recovery-points --backup-vault-name production-vault
   
   # Verify S3 versioning
   aws s3api list-object-versions --bucket production-data-bucket
   ```

#### Recovery Actions (30 minutes - 4 hours)

1. **Point-in-Time Recovery**
   ```bash
   # Restore to specific timestamp
   aws rds restore-db-instance-to-point-in-time \
     --source-db-instance-identifier production-db \
     --target-db-instance-identifier production-db-restored \
     --restore-time 2024-01-01T12:00:00.000Z
   ```

2. **S3 Object Recovery**
   ```bash
   # Restore deleted objects
   aws s3api restore-object --bucket production-data-bucket \
     --key important-file.txt --version-id specific-version-id
   ```

## Recovery Procedures

### Infrastructure Recovery

#### 1. Management Account Recovery

```bash
# Verify Organizations status
aws organizations describe-organization

# Check account status
aws organizations list-accounts

# Restore organizational units if needed
terraform apply -target=module.organization
```

#### 2. Security Services Recovery

```bash
# Restore Security Hub
aws securityhub enable-security-hub --enable-default-standards

# Restore GuardDuty
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Restore Config
aws configservice put-configuration-recorder --configuration-recorder file://config-recorder.json
aws configservice start-configuration-recorder --configuration-recorder-name default
```

#### 3. Network Recovery

```bash
# Restore VPC infrastructure
terraform apply -target=module.vpc

# Restore Transit Gateway
terraform apply -target=module.transit_gateway

# Restore Network Firewall
terraform apply -target=module.network_firewall
```

### Data Recovery

#### 1. Database Recovery

```bash
# List available snapshots
aws rds describe-db-snapshots --db-instance-identifier production-db

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier production-db-restored \
  --db-snapshot-identifier rds:production-db-2024-01-01-12-00

# Update connection strings
kubectl patch configmap app-config -p '{"data":{"db_host":"production-db-restored.region.rds.amazonaws.com"}}'
```

#### 2. File System Recovery

```bash
# Restore EFS from backup
aws efs restore-access-point --access-point-id fsap-12345678 \
  --source-access-point-arn arn:aws:elasticfilesystem:region:account:access-point/fsap-backup

# Mount restored file system
sudo mount -t efs fs-12345678.efs.region.amazonaws.com:/ /mnt/efs
```

#### 3. Object Storage Recovery

```bash
# Restore S3 bucket from backup
aws s3 sync s3://backup-bucket/production-data/ s3://production-data-bucket/ \
  --delete --exact-timestamps

# Restore versioned objects
aws s3api copy-object --copy-source production-data-bucket/file.txt?versionId=version-id \
  --bucket production-data-bucket --key file.txt
```

### Application Recovery

#### 1. Container Recovery

```bash
# Restore ECS services
aws ecs update-service --cluster production --service web-app \
  --desired-count 3 --force-new-deployment

# Restore EKS workloads
kubectl apply -f k8s-manifests/production/
kubectl rollout restart deployment/web-app
```

#### 2. Lambda Recovery

```bash
# Restore Lambda functions
aws lambda update-function-code --function-name production-api \
  --s3-bucket lambda-deployments --s3-key production-api-latest.zip

# Restore function configuration
aws lambda update-function-configuration --function-name production-api \
  --environment Variables='{DB_HOST=restored-db-host,API_KEY=secret-value}'
```

## Testing Procedures

### 1. Monthly DR Tests

```bash
# Test backup restoration
./scripts/test-backup-restore.sh

# Test cross-region failover
./scripts/test-region-failover.sh

# Test data recovery
./scripts/test-data-recovery.sh
```

### 2. Quarterly Full DR Exercise

```bash
# Full environment restoration
./scripts/full-dr-test.sh

# Application failover testing
./scripts/test-application-failover.sh

# Communication procedures test
./scripts/test-communication-plan.sh
```

## Communication Plan

### Internal Notifications

#### Immediate (0-15 minutes)
- Security Operations Center
- On-call engineers
- Service owners

#### Short-term (15-60 minutes)
- Engineering management
- Product teams
- Customer support

#### Extended (1-4 hours)
- Executive leadership
- Legal team
- Public relations

### External Communications

#### Customer Notifications
```
Subject: Service Disruption - [Service Name]

We are currently experiencing a service disruption affecting [affected services]. 
Our team is actively working to restore full functionality.

Status: [INVESTIGATING/IDENTIFIED/MONITORING/RESOLVED]
Impact: [Description of customer impact]
Next Update: [Time of next update]

We apologize for any inconvenience and will provide updates every 30 minutes.
```

#### Status Page Updates
- Initial incident report
- Regular progress updates
- Resolution confirmation
- Post-incident summary

## Recovery Validation

### 1. Service Health Checks

```bash
# Check application endpoints
curl -f https://api.company.com/health

# Verify database connectivity
aws rds describe-db-instances --db-instance-identifier production-db \
  --query 'DBInstances[0].DBInstanceStatus'

# Test authentication services
aws sts get-caller-identity
```

### 2. Data Integrity Verification

```bash
# Verify backup checksums
aws s3api head-object --bucket backup-bucket --key data-backup.tar.gz \
  --query 'Metadata.checksum'

# Test database queries
psql -h restored-db-host -U app_user -d production -c "SELECT COUNT(*) FROM users;"

# Verify file system integrity
fsck /dev/xvdf
```

### 3. Performance Testing

```bash
# Load testing
artillery run load-test-config.yml

# Database performance
pgbench -h restored-db-host -U app_user -d production -c 10 -t 1000

# Network latency
ping -c 10 restored-service-endpoint
```

## Post-Recovery Activities

### 1. Incident Documentation

- Timeline of events
- Root cause analysis
- Recovery actions taken
- Lessons learned
- Process improvements

### 2. System Hardening

```bash
# Apply security patches
aws ssm send-command --document-name "AWS-RunPatchBaseline" \
  --targets "Key=tag:Environment,Values=production"

# Update security configurations
terraform apply -target=module.security_hardening

# Rotate credentials
aws secretsmanager rotate-secret --secret-id production/database/password
```

### 3. Backup Verification

```bash
# Test all backup systems
./scripts/verify-all-backups.sh

# Update backup policies
aws backup put-backup-plan --backup-plan file://updated-backup-plan.json

# Schedule additional backups
aws backup start-backup-job --backup-vault-name production-vault \
  --resource-arn arn:aws:rds:region:account:db:production-db
```

## Contact Information

### Emergency Contacts
- **Primary On-Call**: +1-XXX-XXX-XXXX
- **Secondary On-Call**: +1-XXX-XXX-XXXX
- **Engineering Manager**: +1-XXX-XXX-XXXX
- **CTO**: +1-XXX-XXX-XXXX

### Vendor Contacts
- **AWS Enterprise Support**: Case Portal
- **Database Vendor**: Support Portal
- **Monitoring Vendor**: +1-XXX-XXX-XXXX

### External Services
- **DNS Provider**: Support Portal
- **CDN Provider**: Support Portal
- **Third-party APIs**: Various contact methods