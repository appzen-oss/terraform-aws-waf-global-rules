
# Common Variables
variable "create_rule_group_owasp" {
  type        = bool
  description = "Create WAF rule group of OWASP rules"
  default     = false
}

variable "enable_actions" {
  type        = list(string)
  description = "List of valid actions for enabling indivisual rules"
  default     = ["BLOCK", "COUNT"]
}

variable "enabled" {
  type        = bool
  description = "Enable module. False will disable complete module"
  default     = true
}

variable "environment" {
  type        = string
  description = "Deployment environment name"
}

variable "waf_prefix" {
  type        = string
  description = "A prefix to use for all named resources."
}
