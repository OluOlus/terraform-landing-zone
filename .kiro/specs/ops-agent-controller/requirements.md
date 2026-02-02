# Requirements Document: OpsAgent Actions for Amazon Q Business

## 1. Introduction

The OpsAgent Actions system provides a secure, auditable way for platform engineers to run approved AWS operational actions from Microsoft Teams, using Amazon Q Business as the chat interface. Amazon Q Business handles knowledge/troubleshooting guidance, while OpsAgent Actions API handles controlled operational tasks through an approval workflow.

This approach leverages Amazon Q Business's native Teams integration plus a custom plugin (OpenAPI) that calls a secure backend API, avoiding the need to build a custom Teams bot.

## 2. Scope

### In Scope (MVP)
- Amazon Q Business available in Teams (DM + channel mention behavior)
- A custom plugin ("OpsAgent") that calls your backend (API Gateway → Lambda)
- Read-only diagnostics tools (safe): list/describe resources, CloudWatch metric reads
- Write-capable actions (e.g., EC2 reboot, ECS scaling) behind:
  - Explicit approval workflow
  - Tag scoping (OpsAgentManaged=true)
- Workflow operations for incident management and channel notifications
- Audit logging for all operational actions (not general knowledge chats)

### Out of Scope (MVP)
- Full incident management (PagerDuty/Jira/ServiceNow automation)
- Multi-account cross-org RBAC beyond basic allow-lists
- UI-heavy approvals (adaptive cards). MVP uses a text-based approval token flow
- Auto-remediation without human approval

## 3. Assumptions and Dependencies

### Required Services/Accounts (for sandbox testing)

**AWS Account (sandbox):**
- API Gateway + Lambda
- CloudWatch Logs
- DynamoDB (audit store)
- Optional: SQS DLQ

**Amazon Q Business:**
- Amazon Q Business application configured and enabled
- Custom Plugin created from an OpenAPI schema, pointing to OpsAgent Actions endpoint

**Microsoft 365:**
- Microsoft 365 tenant with Teams enabled
- Permission to install/configure the Amazon Q Business Teams integration

## 4. Glossary

- **Amazon_Q_Business_Teams**: Amazon Q Business integration in Microsoft Teams
- **OpsAgent_Plugin**: Amazon Q Business custom plugin (OpenAPI) enabling actions
- **OpsAgent_Actions_API**: API Gateway endpoint that receives plugin calls
- **OpsAgent_Controller**: Lambda function that validates, approves, executes tools, and logs
- **Approval_Token**: Short-lived token used to confirm write actions
- **Tag_Scoping**: Only resources tagged OpsAgentManaged=true can be modified
- **Audit_Store**: DynamoDB table storing action logs with correlation IDs

## 5. Requirements

### Requirement 1: Teams Interface via Amazon Q Business

**User Story:** As a platform engineer, I want to use Amazon Q Business in Teams for AWS guidance and approved actions.

**Acceptance Criteria:**
1. WHEN a user mentions/uses Amazon Q Business in Teams, IT SHALL respond in Teams with guidance and answers
2. WHEN a user requests an operational action (e.g., "reboot i-123"), Amazon Q Business SHALL be able to invoke the OpsAgent plugin action
3. THE system SHALL publish a short "How to use OpsAgent actions" guide (examples + safety rules)

### Requirement 2: OpsAgent Plugin (OpenAPI) Integration

**User Story:** As a platform engineer, I want operational requests to call a verified backend API.

**Acceptance Criteria:**
1. THE OpsAgent plugin SHALL be defined using an OpenAPI schema supported by Amazon Q Business
2. THE plugin SHALL expose at minimum these operations:
   - `diagnose_*` (read-only)
   - `propose_action` (creates approval token)
   - `approve_action` (executes approved write action)
3. THE plugin SHALL return structured responses that Amazon Q Business can summarize in chat

### Requirement 3: Intent Safety and Default Behavior

**User Story:** As a security administrator, I want the system to default to safe behavior.

**Acceptance Criteria:**
1. WHEN intent is unclear, THE system SHALL default to read-only diagnostics/guidance
2. THE system SHALL never execute a write action in a single step; it MUST require approval (Req 5)
3. THE system SHALL reject requests that attempt to bypass approval

### Requirement 4: Read-only Diagnostics Tools

**User Story:** As a platform engineer, I want quick diagnostics from Teams.

**Acceptance Criteria:**
1. THE OpsAgent_Controller SHALL support these read-only diagnostic operations:
   - `get_ec2_status`: Get EC2 instance status by instance ID or tag filter
   - `get_cloudwatch_metrics`: Retrieve CloudWatch metrics for resources with time windows
   - `describe_alb_target_health`: Check ALB/Target Group health status
   - `search_cloudtrail_events`: Search CloudTrail events with filters and time windows
2. WHEN a diagnostic tool is called, IT SHALL return a concise summary + a structured payload (for logs)
3. ALL diagnostic operations SHALL be read-only and require no approval

### Requirement 5: Write Operations with Approval Workflow

**User Story:** As a platform engineer, I want to perform controlled remediation actions with explicit approval.

**Acceptance Criteria:**
1. THE OpsAgent_Controller SHALL support these write operations (approval required):
   - `reboot_ec2`: Reboot EC2 instance (tag-gated + approval required)
   - `scale_ecs_service`: Scale ECS service desired count (tag-gated + approval required)
2. WHEN a write action is requested, THE system SHALL respond with:
   - Action summary (what will happen)
   - Risk assessment
   - An Approval_Token with 15-minute expiry
   - Instructions: "To proceed, use approve_action with token"
3. WHEN the user calls approve_action with token, THE system SHALL validate:
   - Token is valid + unexpired
   - User is authorized
   - Action parameters match what was proposed
   - Resource is tag-scoped (Req 7)
4. WHEN validation succeeds, THE system SHALL execute the action and return status
5. WHEN validation fails, THE system SHALL NOT execute and SHALL explain why

### Requirement 6: Workflow and Integration Operations

**User Story:** As a platform engineer, I want to create incident records and post summaries for operational workflows.

**Acceptance Criteria:**
1. THE OpsAgent_Controller SHALL support these workflow operations:
   - `create_incident_record`: Create incident record with summary, severity, and links (writes to DynamoDB/SNS)
   - `post_summary_to_channel`: Post operational summary to Teams channel or webhook
2. WORKFLOW operations SHALL NOT require approval but SHALL be fully audited
3. INCIDENT records SHALL be stored in DynamoDB with proper indexing for retrieval

### Requirement 7: Resource Tag Scoping

**User Story:** As a security administrator, I want writes restricted to explicitly-managed resources.

**Acceptance Criteria:**
1. Write actions SHALL only execute on resources tagged: `OpsAgentManaged=true`
2. WHEN tag is missing or false, THE system SHALL block execution and log the attempt
3. TAG validation SHALL occur before any approval token generation

### Requirement 8: Authentication and Authorization

**User Story:** As a security administrator, I want least-privilege execution and user allow-lists.

**Acceptance Criteria:**
1. OpsAgent_Controller SHALL use an IAM role with least privilege for allowed operations
2. THE system SHALL maintain an allow-list of permitted Teams user identities (or mapped identities)
3. WHEN an unauthorized user requests actions, THE system SHALL deny and log

### Requirement 9: Audit Logging and Traceability

**User Story:** As a compliance officer, I want a full audit trail for actions.

**Acceptance Criteria:**
1. Every operational action SHALL generate an audit entry with:
   - Correlation ID
   - User identity
   - Timestamp
   - Tool/action name
   - Parameters (sanitized)
   - Result/status
2. Audit entries SHALL be stored in DynamoDB and/or CloudWatch Logs
3. Secrets/tokens SHALL never be logged in plain text

### Requirement 10: Execution Modes for Safe Testing

**User Story:** As a developer, I want to test without production risk.

**Acceptance Criteria:**
1. The system SHALL support these modes:
   - `LOCAL_MOCK`: no AWS calls, deterministic responses
   - `DRY_RUN`: real read calls allowed, write actions simulated ("WOULD_EXECUTE")
   - `SANDBOX_LIVE`: real writes allowed but only tag-scoped resources
2. Every response SHALL indicate the current mode

### Requirement 11: Reliability and Failure Handling

**User Story:** As a platform engineer, I want clear outcomes when things fail.

**Acceptance Criteria:**
1. Transient AWS/API errors SHALL retry with backoff
2. Failed executions SHALL return a user-friendly message + correlation ID
3. Optional: failures SHALL be sent to an SQS DLQ for later inspection

### Requirement 12: Deployment and Configuration

**User Story:** As an admin, I want a simple deployment path.

**Acceptance Criteria:**
1. The repository SHALL include IaC (SAM or Terraform) to deploy:
   - API Gateway
   - Lambda
   - IAM roles/policies
   - Audit store/logging
2. Deployment docs SHALL include:
   - How to configure the Q Business plugin with the OpenAPI schema
   - How to enable Teams integration for Q Business

### Requirement 13: Test Plan and Verification

**User Story:** As a developer, I want quick proof the system works end-to-end.

**Acceptance Criteria:**
1. Repo SHALL include sample test scripts for:
   - Propose/approve flow
   - Dry-run behavior
   - Tag scoping enforcement
2. The system SHALL provide a "smoke test checklist":
   - Q in Teams responds
   - Plugin call works
   - Propose returns token
   - Approve executes (sandbox tagged resource only)
   - Audit log entry exists

## 6. Operations Catalog

The OpsAgent Actions system SHALL support the following operations organized by category:

### 6.1 Read-Only Diagnostic Operations
1. **get_ec2_status**(instanceId|tagFilter) - Get EC2 instance status and basic metrics
2. **get_cloudwatch_metrics**(resource, metric, window) - Retrieve CloudWatch metrics with time windows
3. **describe_alb_target_health**(albArn|tgArn) - Check ALB/Target Group health status
4. **search_cloudtrail_events**(filter, window) - Search CloudTrail events with filters

### 6.2 Write Operations (Approval Required)
5. **reboot_ec2**(instanceId) - Reboot EC2 instance (tag-gated + approval required)
6. **scale_ecs_service**(cluster, service, desiredCount) - Scale ECS service (tag-gated + approval required)

### 6.3 Workflow Operations
7. **create_incident_record**(summary, severity, links) - Create incident record (writes to DynamoDB/SNS)
8. **post_summary_to_channel**(text) - Post operational summary to Teams channel or webhook

## 7. Architecture Constraints

- **Serverless**: AWS Lambda + API Gateway architecture
- **Security-First**: All write operations require explicit approval
- **Audit-First**: All actions must be logged before execution
- **Tag-Scoped**: Write operations restricted to tagged resources only
- **Mode-Aware**: Support for mock, dry-run, and live execution modes