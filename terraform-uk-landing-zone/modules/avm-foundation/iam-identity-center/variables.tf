variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "enable_break_glass_monitoring" {
  description = "Enable CloudWatch monitoring and alerting for break glass access"
  type        = bool
  default     = true
}

variable "break_glass_alarm_actions" {
  description = "List of actions to execute when break glass access is used (e.g., SNS topic ARNs)"
  type        = list(string)
  default     = []
}

variable "uk_regions" {
  description = "List of allowed specified regions for compliance"
  type        = list(string)
  default     = ["us-west-2", "us-east-1"]
}

variable "session_durations" {
  description = "Session durations for different permission sets"
  type = object({
    security_admin = optional(string, "PT4H")
    network_admin  = optional(string, "PT4H")
    developer      = optional(string, "PT8H")
    viewer         = optional(string, "PT8H")
    break_glass    = optional(string, "PT1H")
  })
  default = {}
}

variable "mfa_max_age_seconds" {
  description = "Maximum age of MFA authentication in seconds for different roles"
  type = object({
    security_admin = optional(number, 3600)  # 1 hour
    network_admin  = optional(number, 3600)  # 1 hour
    developer      = optional(number, 7200)  # 2 hours
    viewer         = optional(number, 28800) # 8 hours
    break_glass    = optional(number, 300)   # 5 minutes
  })
  default = {}
}
