
# Rate limit - HTTP Flood

variable "rule_rate_limit_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_rate_limit_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 5
}
variable "rule_rate_limit_count" {
  type        = number
  description = "The number requests allowed over a 5 minute period (minimum value of 100 is enforced)"
  default     = 100
}
variable "rule_rate_limit_paths" {
  type        = list(string)
  description = "A list of relative URL paths to rate limit"
  default     = []
}
locals {
  # Determine if Rate Limiting is enabled
  is_rate_limit_enabled = var.enabled && contains(var.enable_actions, var.rule_rate_limit_action) ? 1 : 0
}

resource "aws_waf_rate_based_rule" "rate_limit" {
  count       = local.is_rate_limit_enabled
  name        = "${var.waf_prefix}-rate-limit"
  metric_name = replace("${var.waf_prefix}ratelimit", "/[^0-9A-Za-z]/", "")
  rate_key    = "IP"
  rate_limit  = var.rule_rate_limit_count
  predicates {
    data_id = aws_waf_byte_match_set.rate_limit[0].id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_byte_match_set" "rate_limit" {
  count = local.is_rate_limit_enabled
  name  = "${var.waf_prefix}-rate-limit"
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_rate_limit_paths
    content {
      target_string         = x.value
      text_transformation   = "LOWERCASE"
      positional_constraint = "STARTS_WITH"
      field_to_match {
        type = "URI"
      }
    }
  }
}
