
variable "rule_blacklist_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_blacklist_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 1
}

locals {
  is_blacklist_enabled = var.enabled && contains(var.enable_actions, var.rule_blacklist_action) ? 1 : 0
}

resource "aws_waf_ipset" "blacklist" {
  count = local.is_blacklist_enabled
  name = "${var.waf_prefix}-blacklist"
  lifecycle {
    ignore_changes = [
      ip_set_descriptors,
    ]
  }
}

resource "aws_waf_rule" "blacklist" {
  depends_on = [aws_waf_ipset.blacklist]
  count = local.is_blacklist_enabled
  name = "${var.waf_prefix}-blacklist"
  metric_name = replace("${var.waf_prefix}blacklistWafRule", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_ipset.blacklist[0].id
    negated = false
    type = "IPMatch"
  }
}
