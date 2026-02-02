# Security Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for responding to security incidents in the AWS Secure Landing Zone.

## Incident Classification

### Severity Levels

- **Critical (P1)**: Active breach, data exfiltration, or system compromise
- **High (P2)**: Potential breach, suspicious activity, or security control failure
- **Medium (P3)**: Policy violations, configuration drift, or compliance issues
- **Low (P4)**: Informational alerts, routine security events

## Response Procedures

### 1. Initial Response (0-15 minutes)

#### For Critical/High Severity Incidents:

1. **Acknowledge the Alert**
   ```bash
   # Check Security Hub findings
   aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'
   
   # Check GuardDuty findings
   aws guardduty list-findings --detector-id <detector-id> --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'
   ```

2. **Assess the Scope**
   - Identify affected accounts and resources
   - Determine potential data exposure
   - Check for lateral movement indicators

3. **Contain the Threat**
   ```bash
   # Isolate compromised EC2 instances
   aws ec2 modify-instance-attribute --instance-id <instance-id> --groups sg-isolation
   
   # Disable compromised IAM users
   aws iam put-user-policy --user-name <username> --policy-name DenyAll --policy-document file://deny-all-policy.json
   
   # Revoke active sessions
   aws iam delete-login-profile --user-name <username>
   ```

### 2. Investigation (15-60 minutes)

#### Evidence Collection

1. **CloudTrail Analysis**
   ```bash
   # Search for suspicious API calls
   aws logs filter-log-events --log-group-name CloudTrail/SecurityEvents \
     --start-time $(date -d '1 hour ago' +%s)000 \
     --filter-pattern '{ $.errorCode = "*" || $.sourceIPAddress != "AWS Internal" }'
   ```

2. **VPC Flow Logs**
   ```bash
   # Analyze network traffic
   aws logs filter-log-events --log-group-name VPCFlowLogs \
     --start-time $(date -d '1 hour ago' +%s)000 \
     --filter-pattern '[version, account, eni, source, destination, srcport, destport="22" || destport="3389", protocol, packets, bytes, windowstart, windowend, action="REJECT", flowlogstatus]'
   ```

3. **Config Timeline**
   ```bash
   # Check configuration changes
   aws configservice get-resource-config-history \
     --resource-type AWS::IAM::User \
     --resource-id <resource-id> \
     --earlier-time $(date -d '24 hours ago' --iso-8601)
   ```

#### Root Cause Analysis

1. **Timeline Construction**
   - Map events chronologically
   - Identify initial compromise vector
   - Track attacker progression

2. **Impact Assessment**
   - Data accessed or modified
   - Systems compromised
   - Compliance implications

### 3. Eradication (1-4 hours)

#### Remove Threats

1. **Malware Removal**
   ```bash
   # Terminate compromised instances
   aws ec2 terminate-instances --instance-ids <instance-id>
   
   # Launch clean replacement from AMI
   aws ec2 run-instances --image-id <clean-ami-id> --instance-type t3.medium
   ```

2. **Account Cleanup**
   ```bash
   # Remove unauthorized users
   aws iam delete-user --user-name <unauthorized-user>
   
   # Rotate compromised credentials
   aws iam create-access-key --user-name <user>
   aws iam delete-access-key --user-name <user> --access-key-id <old-key>
   ```

3. **Network Isolation**
   ```bash
   # Update security groups
   aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0
   ```

### 4. Recovery (2-8 hours)

#### System Restoration

1. **Backup Restoration**
   ```bash
   # Restore from clean backup
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier restored-db \
     --db-snapshot-identifier clean-snapshot-id
   ```

2. **Configuration Hardening**
   ```bash
   # Apply security baselines
   terraform apply -target=module.security_hardening
   
   # Update security groups
   terraform apply -target=module.network_security
   ```

3. **Monitoring Enhancement**
   ```bash
   # Enable additional logging
   aws logs create-log-group --log-group-name /aws/security/enhanced
   
   # Create custom CloudWatch alarms
   aws cloudwatch put-metric-alarm --alarm-name "Suspicious-API-Calls" \
     --alarm-description "Detects unusual API activity" \
     --metric-name "ErrorCount" --namespace "AWS/CloudTrail"
   ```

### 5. Post-Incident Activities (24-48 hours)

#### Documentation

1. **Incident Report**
   - Timeline of events
   - Root cause analysis
   - Impact assessment
   - Lessons learned

2. **Evidence Preservation**
   ```bash
   # Create forensic snapshots
   aws ec2 create-snapshot --volume-id <volume-id> --description "Forensic evidence"
   
   # Export CloudTrail logs
   aws s3 cp s3://cloudtrail-bucket/logs/ ./evidence/ --recursive
   ```

#### Process Improvement

1. **Security Control Updates**
   - Patch identified vulnerabilities
   - Enhance monitoring rules
   - Update access controls

2. **Training and Awareness**
   - Conduct incident review
   - Update procedures
   - Train response team

## Escalation Procedures

### Internal Escalation

1. **Level 1**: Security Operations Team
2. **Level 2**: Security Manager
3. **Level 3**: CISO/CTO
4. **Level 4**: Executive Leadership

### External Escalation

1. **Law Enforcement**: For criminal activity
2. **Regulatory Bodies**: For compliance violations
3. **Customers**: For data breaches
4. **Partners**: For supply chain impacts

## Communication Templates

### Internal Notification

```
SECURITY INCIDENT ALERT

Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Incident ID: SEC-YYYY-MMDD-###
Time Detected: [TIMESTAMP]
Affected Systems: [SYSTEMS/ACCOUNTS]
Initial Assessment: [BRIEF DESCRIPTION]
Response Team: [TEAM MEMBERS]
Next Update: [TIME]

Current Status: [INVESTIGATING/CONTAINING/RECOVERING]
```

### Executive Summary

```
EXECUTIVE SECURITY BRIEFING

Incident: [BRIEF TITLE]
Impact: [BUSINESS IMPACT]
Status: [CURRENT STATUS]
Timeline: [KEY MILESTONES]
Actions Taken: [SUMMARY]
Next Steps: [PLANNED ACTIONS]
Estimated Resolution: [TIME]
```

## Tools and Resources

### AWS Security Services

- **Security Hub**: Centralized security findings
- **GuardDuty**: Threat detection
- **Config**: Configuration monitoring
- **CloudTrail**: API audit logging
- **VPC Flow Logs**: Network traffic analysis

### External Tools

- **SIEM Integration**: Splunk, Elastic, etc.
- **Threat Intelligence**: Commercial feeds
- **Forensics Tools**: Volatility, Autopsy
- **Communication**: Slack, Teams, PagerDuty

## Contact Information

### Internal Contacts

- **Security Operations Center**: +1-XXX-XXX-XXXX
- **Security Manager**: security-manager@company.com
- **CISO**: ciso@company.com
- **Legal**: legal@company.com

### External Contacts

- **AWS Support**: Enterprise Support Case
- **Law Enforcement**: Local FBI Cyber Division
- **Incident Response Vendor**: [If applicable]

## Appendices

### A. Common IOCs (Indicators of Compromise)

- Unusual login locations
- Off-hours administrative activity
- Large data transfers
- New user account creation
- Privilege escalation attempts

### B. Forensic Artifacts

- CloudTrail logs
- VPC Flow Logs
- EBS snapshots
- Memory dumps
- Network packet captures

### C. Legal Considerations

- Evidence preservation requirements
- Notification obligations
- Regulatory compliance
- Chain of custody procedures