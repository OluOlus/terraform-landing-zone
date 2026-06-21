## Summary

<!-- What does this PR do? One paragraph is enough. -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing deployments to fail)
- [ ] Security fix or hardening
- [ ] Documentation update
- [ ] Refactoring (no functional change)
- [ ] CI/CD improvement

## Modules / Environments Changed

<!-- List the modules or environments this PR touches -->

- [ ] `modules/security-services/guardduty`
- [ ] `modules/security-services/security-hub`
- [ ] `modules/security-services/security-automation`
- [ ] `modules/security-services/config`
- [ ] `modules/logging/`
- [ ] `modules/networking/`
- [ ] `modules/management/`
- [ ] `modules/avm-foundation/`
- [ ] `modules/security/kms`
- [ ] `modules/storage/s3`
- [ ] `environments/management`
- [ ] `environments/security`
- [ ] `environments/logging`
- [ ] `environments/networking`
- [ ] `environments/production-uk`
- [ ] `environments/non-production-uk`
- [ ] `environments/sandbox`
- [ ] `.github/workflows`
- [ ] `policies/`
- [ ] `scripts/`

## Checklist

### Code Quality
- [ ] `terraform fmt -recursive .` has been run
- [ ] `terraform validate` passes for all changed environments
- [ ] `tflint` passes with no new warnings
- [ ] Pre-commit hooks pass: `pre-commit run --all-files`

### Security
- [ ] No secrets, account IDs, or real email addresses in committed code
- [ ] IAM policies follow least-privilege (no new `Resource = "*"` on destructive actions)
- [ ] All new S3 buckets have public access block, versioning, and KMS encryption
- [ ] All new Lambda functions have `dead_letter_config`
- [ ] Region variables are not hardcoded (use `data.aws_region.current.name`)
- [ ] `tfsec` and `checkov` pass with no new HIGH/CRITICAL findings

### Documentation
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Variables and outputs have `description` fields
- [ ] Module `README.md` regenerated with `terraform-docs` if variables/outputs changed

### Testing
- [ ] Terraform plan reviewed (the PR plan workflow will post it as a comment)
- [ ] Unit tests pass: `make test-unit`

## Terraform Plan Summary

<!-- The PR plan workflow will automatically post a plan diff as a comment.
     Paste the summary of impactful changes here once it appears:

     Plan: X to add, Y to change, Z to destroy.

     List any destructive changes (destroy/replace) explicitly.
-->

## Additional Notes

<!-- Anything reviewers should know: rollback plan, dependency order, blast radius, etc. -->
