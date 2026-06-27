# Outputs for AWS Control Tower Landing Zone Module

output "landing_zone_arn" {
  description = "ARN of the AWS Control Tower landing zone."
  value       = try(aws_controltower_landing_zone.this[0].arn, null)
}

output "landing_zone_id" {
  description = "ID of the AWS Control Tower landing zone."
  value       = try(aws_controltower_landing_zone.this[0].id, null)
}

output "enabled_controls" {
  description = "Control Tower controls enabled by this module."
  value = {
    for key, control in aws_controltower_control.this : key => {
      id                 = control.id
      control_identifier = control.control_identifier
      target_identifier  = control.target_identifier
      arn                = control.arn
    }
  }
}
