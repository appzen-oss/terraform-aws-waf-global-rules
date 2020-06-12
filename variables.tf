
# Common Variables
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

variable "waf_prefix" {
  type        = string
  description = "A prefix to use for all named resources."
}
