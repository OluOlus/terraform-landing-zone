# Implementation Plan: OpsAgent Actions for Amazon Q Business

## Overview

This implementation plan converts the OpsAgent Actions design into discrete coding tasks for a Python-based serverless system on AWS. The system provides a secure backend API for Amazon Q Business plugin operations, supporting 8 operations across 3 categories: diagnostic (4), write (2), and workflow (2).

## Tasks

- [ ] 1. Set up project structure and OpenAPI schema
  - [x] 1.1 Create Python project structure for plugin backend
    - Create src/, tests/, and infrastructure/ directories
    - Set up AWS SAM template for API Gateway with OpenAPI schema
    - Configure development environment with boto3, pytest, and hypothesis
    - Define OpenAPI 3.0 schema for all 8 operations
    - _Requirements: 2.1, 2.2, 12.1_
  
  - [x] 1.2 Create core data models for plugin operations
    - Define Python dataclasses for PluginRequest, PluginResponse, and OperationResult
    - Implement correlation ID generation and tracking throughout request lifecycle
    - Create request validation and sanitization functions for plugin parameters
    - Add user context extraction from Amazon Q Business requests
    - _Requirements: 1.1, 8.2, 9.1_

- [ ] 2. Implement authentication and authorization system
  - [x] 2.1 Create user authentication and authorization
    - Implement user identity extraction from Amazon Q Business context
    - Create user allow-list validation using SSM Parameter Store
    - Add request signature validation for plugin security
    - Implement correlation ID tracking for audit purposes
    - _Requirements: 8.1, 8.2, 9.1_
  
  - [ ]* 2.2 Write property test for authentication validation
    - **Property 1: Authentication Validation**
    - **Validates: Requirements 8.2, 8.3**

- [ ] 3. Implement tool execution engine with security controls
  - [x] 3.1 Create tool guardrails and policy engine
    - Implement ToolGuardrails class with operation allow-list validation
    - Create parameter schema validation using JSON Schema
    - Add execution mode enforcement (LOCAL_MOCK, DRY_RUN, SANDBOX_LIVE)
    - Implement resource tagging validation for OpsAgentManaged=true
    - _Requirements: 3.1, 7.1, 7.2, 10.1_
  
  - [ ]* 3.2 Write property test for security controls
    - **Property 2: Tag Scoping Enforcement**
    - **Validates: Requirements 7.1, 7.2**
  
  - [x] 3.3 Implement tool execution engine
    - Create ToolExecutionEngine class with executeOperation method
    - Add operation routing for diagnostic, write, and workflow operations
    - Implement error handling and graceful failure recovery
    - Create execution mode switching logic with proper responses
    - _Requirements: 2.2, 3.1, 10.1, 11.1_
  
  - [ ]* 3.4 Write property test for execution consistency
    - **Property 3: Mode Consistency**
    - **Validates: Requirements 10.1, 10.2**

- [ ] 4. Implement diagnostic operations (4 operations)
  - [x] 4.1 Create get_ec2_status operation
    - Implement EC2 instance health and metrics retrieval by ID or tag filter
    - Add CloudWatch metrics integration for CPU, memory, network
    - Create structured response format for Amazon Q Business display
    - Handle AWS API errors with user-friendly error messages
    - _Requirements: 4.1, 4.2_
  
  - [x] 4.2 Create get_cloudwatch_metrics operation
    - Implement CloudWatch metrics retrieval with time windows
    - Add metric aggregation and statistical analysis
    - Format metrics data for chat display with proper units
    - Support multiple metric namespaces and dimensions
    - _Requirements: 4.1, 4.2_
  
  - [x] 4.3 Create describe_alb_target_health operation
    - Implement ALB/Target Group health status checking
    - Add target health analysis and unhealthy target identification
    - Create load balancer state reporting
    - Handle ELBv2 API errors and edge cases
    - _Requirements: 4.1, 4.2_
  
  - [x] 4.4 Create search_cloudtrail_events operation
    - Implement CloudTrail event search with filters and time windows
    - Add event filtering by event name and resource name
    - Format CloudTrail events for chat display
    - Handle CloudTrail API limitations and pagination
    - _Requirements: 4.1, 4.2_
  
  - [ ]* 4.5 Write property test for read-only guarantee
    - **Property 4: Read-Only Guarantee**
    - **Validates: Requirements 4.1, 4.2, 4.3**

- [ ] 5. Implement approval gate system
  - [x] 5.1 Create approval token management
    - Implement ApprovalGate class with cryptographic token generation
    - Add token expiration and one-time use enforcement (15 minutes)
    - Create token-to-action binding to prevent parameter tampering
    - Store approval state in DynamoDB with TTL
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  
  - [x] 5.2 Create propose_action operation
    - Implement action proposal with risk assessment
    - Generate approval tokens with action summary and instructions
    - Add parameter validation and resource existence checks
    - Format approval requests for Amazon Q Business display
    - _Requirements: 5.1, 5.2_
  
  - [ ]* 5.3 Write property test for approval enforcement
    - **Property 5: Approval Enforcement**
    - **Validates: Requirements 5.1, 5.2, 5.3**

- [ ] 6. Implement write operations with approval workflow (2 operations)
  - [x] 6.1 Create approve_action operation
    - Implement token validation and consumption logic
    - Add user authorization validation for approval
    - Execute approved actions with proper error handling
    - Return execution status and confirmation details
    - _Requirements: 5.3, 5.4_
  
  - [x] 6.2 Create reboot_ec2 write operation
    - Implement EC2RebootTool with tag validation (OpsAgentManaged=true)
    - Add dry-run simulation that returns "WOULD_EXECUTE"
    - Create execution confirmation and status reporting
    - Handle AWS API errors and rate limiting
    - _Requirements: 5.4, 7.1, 7.2_
  
  - [x] 6.3 Create scale_ecs_service write operation
    - Implement ECS service scaling with tag validation
    - Add desired count validation and service existence checks
    - Create scaling status monitoring and confirmation
    - Handle ECS API errors and service update limitations
    - _Requirements: 5.4, 7.1, 7.2_
  
  - [ ]* 6.4 Write property test for write operation security
    - **Property 2: Tag Scoping Enforcement** (test write operation enforcement)
    - **Validates: Requirements 7.1, 7.2**

- [ ] 7. Implement workflow operations (2 operations)
  - [x] 7.1 Create create_incident_record operation
    - Implement incident record creation with summary, severity, and links
    - Add DynamoDB storage with proper indexing for retrieval
    - Create SNS notification publishing for incident alerts
    - Format incident records for tracking and reporting
    - _Requirements: 6.1, 6.2, 6.3_
  
  - [x] 7.2 Create post_summary_to_channel operation
    - Implement Teams channel posting via webhook or SNS
    - Add message formatting and delivery confirmation
    - Create fallback mechanisms for delivery failures
    - Handle webhook authentication and rate limiting
    - _Requirements: 6.1, 6.2, 6.3_

- [ ] 8. Implement comprehensive audit logging
  - [x] 8.1 Create audit logger with structured logging
    - Implement AuditLogger class with correlation ID tracking
    - Add user identity and operation parameter logging
    - Create log sanitization to prevent secret exposure
    - Support both CloudWatch Logs and DynamoDB storage
    - _Requirements: 9.1, 9.2, 9.3_
  
  - [ ]* 8.2 Write property test for audit completeness
    - **Property 6: Audit Completeness**
    - **Validates: Requirements 9.1, 9.2**
  
  - [ ]* 8.3 Write property test for secret hygiene
    - **Property 7: Secret Hygiene**
    - **Validates: Requirements 9.3**

- [ ] 9. Implement API Gateway integration and plugin endpoints
  - [x] 9.1 Create Lambda handler for plugin operations
    - Implement main Lambda handler for Amazon Q Business plugin requests
    - Add request routing for diagnostic, propose, approve, and workflow operations
    - Create response formatting for plugin schema compliance
    - Implement rate limiting and request throttling
    - _Requirements: 2.2, 11.1, 11.2_
  
  - [x] 9.2 Implement health and status endpoints
    - Create /health endpoint with execution mode reporting
    - Add AWS service connectivity validation
    - Return structured health information for monitoring
    - Include plugin schema version and API status
    - _Requirements: 12.1, 13.1_
  
  - [ ]* 9.3 Write property test for plugin response format
    - **Property 8: Plugin Response Format**
    - **Validates: Requirements 2.2, 2.3**

- [x] 10. Infrastructure provisioning and deployment
  - [x] 10.1 Complete AWS SAM template with OpenAPI integration
    - Define API Gateway with OpenAPI 3.0 schema for all 8 operations
    - Configure Lambda with appropriate memory and timeout settings
    - Create IAM roles with least privilege permissions for all AWS services
    - Set up CloudWatch Logs, DynamoDB tables (audit + incidents), and SSM parameters
    - _Requirements: 12.1, 12.2_
  
  - [x] 10.2 Create Amazon Q Business plugin configuration
    - Generate complete OpenAPI schema file for Amazon Q Business plugin creation
    - Document plugin setup instructions for Amazon Q Business console
    - Create environment-specific configuration templates
    - Add plugin testing and validation procedures
    - _Requirements: 2.1, 12.2, 13.2_
  
  - [x] 10.3 Create deployment scripts and documentation
    - Write deployment commands for different environments
    - Create configuration management for execution modes
    - Document credential setup and plugin registration
    - Add troubleshooting guide for common deployment issues
    - _Requirements: 12.2, 13.2_

- [-] 11. Testing infrastructure and validation
  - [x] 11.1 Implement unit tests for all operations
    - Create comprehensive unit tests for all 8 plugin operations
    - Test approval workflow with mock tokens and validation
    - Add error handling tests for AWS API failures
    - Test execution mode switching and response formatting
    - _Requirements: 13.1, 13.2_
  
  - [x] 11.2 Implement integration tests for plugin workflow
    - Create end-to-end tests simulating Amazon Q Business plugin calls
    - Test complete approval workflow from propose to execute
    - Validate audit logging across all operations
    - Test error scenarios and edge cases
    - _Requirements: 13.1, 13.2_
  
  - [ ]* 11.3 Write comprehensive property-based test suite
    - Implement all 8 correctness properties as property tests
    - Configure hypothesis with custom generators for plugin requests
    - Set up test tagging with requirement references
    - Run tests with minimum 100 iterations per property
    - _Requirements: All correctness properties_

- [x] 12. Final validation and smoke testing
  - [x] 12.1 Create smoke test suite for deployed system
    - Implement automated tests for infrastructure provisioning
    - Create plugin operation validation tests for all 8 operations
    - Add approval workflow end-to-end testing
    - Test audit logging and monitoring integration
    - _Requirements: 13.1, 13.2_
  
  - [x] 12.2 Create Amazon Q Business integration guide
    - Document complete setup process for Amazon Q Business plugin
    - Create sample plugin requests and expected responses for all operations
    - Add troubleshooting guide for common integration issues
    - Include security best practices and operational guidelines
    - _Requirements: 1.1, 12.2, 13.2_

## Operations Summary

### Diagnostic Operations (No Approval Required)
1. **get_ec2_status** - EC2 instance health and metrics
2. **get_cloudwatch_metrics** - CloudWatch metrics retrieval
3. **describe_alb_target_health** - ALB/Target Group health
4. **search_cloudtrail_events** - CloudTrail event search

### Write Operations (Approval Required)
5. **reboot_ec2** - EC2 instance reboot (tag-gated)
6. **scale_ecs_service** - ECS service scaling (tag-gated)

### Workflow Operations (No Approval, Fully Audited)
7. **create_incident_record** - Incident management
8. **post_summary_to_channel** - Teams notifications

## Notes

- Tasks marked with `*` are optional property-based tests that can be skipped for faster MVP
- Each task references specific requirements for traceability
- All 8 operations must be implemented for complete functionality
- OpenAPI schema drives Amazon Q Business plugin integration
- Write operations require explicit approval workflow with 15-minute token expiry
- Tag-based resource scoping (OpsAgentManaged=true) enforced for write operations
- Comprehensive audit logging for all operational actions
- Support for multiple execution modes: LOCAL_MOCK, DRY_RUN, SANDBOX_LIVE
- Infrastructure includes multiple DynamoDB tables: audit logs and incident records
- SNS integration for notifications and incident management