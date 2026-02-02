# Requirements Document

## Introduction

The GuardDuty Sentinel Integration is a production-ready KQL parsing and normalization solution for AWS GuardDuty findings in Microsoft Sentinel. The system leverages Microsoft's existing AWS S3 connector to provide comprehensive data parsing, ASIM normalization, and operational troubleshooting capabilities for security teams using Microsoft Sentinel with AWS GuardDuty.

## Glossary

- **System**: The GuardDuty Sentinel Integration solution
- **Parser**: KQL function that transforms raw GuardDuty JSON into structured data
- **ASIM**: Azure Sentinel Information Model for cross-source data normalization
- **Connector**: Microsoft Sentinel AWS S3 connector for data ingestion
- **Finding**: Individual security event detected by AWS GuardDuty
- **Workspace**: Microsoft Sentinel Log Analytics workspace
- **Config_Function**: Centralized configuration management function
- **Smoke_Test**: Automated validation query to verify system health

## Requirements

### Requirement 1: Core KQL Parsing

**User Story:** As a security analyst, I want to query GuardDuty findings using structured fields, so that I can efficiently investigate security events without parsing raw JSON.

#### Acceptance Criteria

1. WHEN raw GuardDuty JSON data is available in the workspace, THE System SHALL parse it into structured fields including FindingId, FindingType, Severity, Title, Description, AwsAccountId, and AwsRegion
2. WHEN parsing GuardDuty data, THE System SHALL standardize severity levels into High, Medium, Low, and Informational categories based on numeric severity scores
3. WHEN a parsing function is called with a time range parameter, THE System SHALL return only findings within that specified timeframe
4. WHEN parsing fails for individual records, THE System SHALL continue processing other records and exclude invalid entries from results
5. THE System SHALL preserve the original raw JSON data alongside parsed fields for advanced analysis

### Requirement 2: ASIM Network Session Normalization

**User Story:** As a threat hunter, I want GuardDuty network findings normalized to ASIM schema, so that I can correlate them with other network data sources in cross-source hunting queries.

#### Acceptance Criteria

1. WHEN GuardDuty network findings are processed, THE System SHALL map source and destination IP addresses to ASIM SrcIpAddr and DstIpAddr fields
2. WHEN network findings contain port information, THE System SHALL map them to ASIM SrcPortNumber and DstPortNumber fields
3. WHEN geographic information is available, THE System SHALL populate ASIM SrcGeoCountry and DstGeoCountry fields
4. WHEN threat categorization is possible, THE System SHALL assign appropriate ASIM ThreatCategory values based on GuardDuty finding types
5. THE System SHALL include all required ASIM Network Session schema fields with appropriate default values when source data is unavailable

### Requirement 3: Configuration Management

**User Story:** As a system administrator, I want centralized configuration for table names and parsing settings, so that I can customize the solution for different environments without modifying individual functions.

#### Acceptance Criteria

1. THE Config_Function SHALL provide configurable table names, column names, and default time ranges through a single configuration interface
2. WHEN configuration values are updated, THE System SHALL apply changes to all parsing functions without requiring individual function modifications
3. WHEN invalid configuration values are provided, THE System SHALL use safe default values and continue operation
4. THE System SHALL support configuration of the source table name, raw data column name, and default lookback period
5. WHEN deployed to different environments, THE System SHALL allow environment-specific configuration through deployment parameters

### Requirement 4: Specialized Parsing Functions

**User Story:** As a security analyst, I want specialized parsers for network and IAM findings, so that I can focus on specific types of security events with relevant contextual information.

#### Acceptance Criteria

1. WHEN network-related GuardDuty findings are available, THE Network_Parser SHALL extract remote IP addresses, ports, protocols, and geographic information
2. WHEN IAM-related GuardDuty findings are available, THE IAM_Parser SHALL extract API call names, user identities, access key information, and authentication details
3. WHEN specialized parsers are called, THE System SHALL return only findings relevant to that specific domain (network or IAM)
4. WHEN no relevant findings exist for a specialized parser, THE System SHALL return an empty result set without errors
5. THE System SHALL maintain consistent field naming and data types across all specialized parsing functions

### Requirement 5: Operational Validation and Health Monitoring

**User Story:** As a system administrator, I want automated validation queries and health checks, so that I can quickly identify and troubleshoot data ingestion or parsing issues.

#### Acceptance Criteria

1. WHEN smoke tests are executed, THE System SHALL validate data availability, structure integrity, and parsing function operation
2. WHEN troubleshooting queries are run, THE System SHALL provide diagnostic information about connector status, data quality, and common configuration issues
3. WHEN data ingestion problems occur, THE System SHALL provide specific guidance for common issues including KMS permissions, S3 bucket access, and SQS queue configuration
4. THE System SHALL validate that required fields are present in parsed data and report data quality metrics
5. WHEN system health is checked, THE System SHALL report on finding type diversity, data freshness, and parsing success rates

### Requirement 6: Deployment and Infrastructure Management

**User Story:** As a DevOps engineer, I want automated deployment templates and infrastructure as code, so that I can deploy the solution consistently across multiple environments.

#### Acceptance Criteria

1. WHEN deployment templates are executed, THE System SHALL create all required KQL functions in the specified Log Analytics workspace
2. WHEN ARM or Bicep templates are used, THE System SHALL support parameterized configuration for different environments
3. WHEN deployment is complete, THE System SHALL provide validation steps to confirm successful installation
4. THE System SHALL support deployment through Azure CLI, PowerShell, and Azure portal interfaces
5. WHEN deployment parameters are invalid, THE System SHALL provide clear error messages and fail gracefully

### Requirement 7: Documentation and Troubleshooting Support

**User Story:** As a security team member, I want comprehensive documentation and troubleshooting guides, so that I can successfully deploy, configure, and maintain the GuardDuty integration.

#### Acceptance Criteria

1. WHEN users encounter connector setup issues, THE System SHALL provide step-by-step guides for AWS S3 connector configuration
2. WHEN data ingestion problems occur, THE System SHALL provide diagnostic queries and solutions for common issues including KMS permissions and S3 access
3. WHEN parsing functions return unexpected results, THE System SHALL provide troubleshooting steps to identify and resolve data format or configuration issues
4. THE System SHALL include sample queries demonstrating common use cases for threat hunting and security analysis
5. WHEN system performance issues arise, THE System SHALL provide optimization guidance for query performance and resource usage

### Requirement 8: Data Quality and Error Handling

**User Story:** As a security analyst, I want reliable data parsing with graceful error handling, so that I can trust the parsed data for security investigations and automated analysis.

#### Acceptance Criteria

1. WHEN malformed JSON data is encountered, THE System SHALL skip invalid records and continue processing valid data
2. WHEN required GuardDuty fields are missing, THE System SHALL provide default values or null indicators without failing the entire parsing operation
3. WHEN data type conversions fail, THE System SHALL handle errors gracefully and preserve the original data for manual inspection
4. THE System SHALL validate that parsed timestamps are within reasonable ranges and flag anomalous values
5. WHEN parsing large datasets, THE System SHALL maintain consistent performance and avoid timeout errors through efficient query design

### Requirement 9: Integration with Microsoft Sentinel Ecosystem

**User Story:** As a security operations center analyst, I want the GuardDuty integration to work seamlessly with existing Sentinel features, so that I can incorporate GuardDuty data into existing workflows and automation.

#### Acceptance Criteria

1. WHEN GuardDuty data is parsed, THE System SHALL use standard Sentinel field naming conventions for compatibility with existing analytics rules
2. WHEN ASIM normalization is applied, THE System SHALL ensure compatibility with Microsoft's cross-source hunting capabilities
3. WHEN parsed data is used in analytics rules, THE System SHALL provide consistent data types and formats for reliable rule execution
4. THE System SHALL support integration with Sentinel workbooks, hunting queries, and automated response playbooks
5. WHEN new GuardDuty finding types are introduced by AWS, THE System SHALL handle them gracefully without breaking existing functionality

### Requirement 10: Performance and Scalability

**User Story:** As a system administrator, I want the parsing solution to handle high-volume GuardDuty data efficiently, so that query performance remains acceptable even with large datasets.

#### Acceptance Criteria

1. WHEN processing large time ranges, THE System SHALL provide guidance on optimal query patterns and time range limitations
2. WHEN multiple users run concurrent queries, THE System SHALL maintain acceptable response times through efficient KQL design
3. WHEN data volume increases, THE System SHALL scale appropriately without requiring architectural changes
4. THE System SHALL provide recommendations for query optimization and performance tuning
5. WHEN resource constraints are encountered, THE System SHALL provide clear guidance on scaling options and best practices