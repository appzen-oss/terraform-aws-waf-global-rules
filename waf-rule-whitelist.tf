
variable "rule_whitelist_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_whitelist_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 95
}

locals {
  is_whitelist_enabled = var.enabled && contains(var.enable_actions, var.rule_whitelist_action) ? 1 : 0
}

resource "aws_waf_ipset" "whitelist" {
  count = local.is_whitelist_enabled
  name = "${var.waf_prefix}-whitelist"
  lifecycle {
    ignore_changes = [
      ip_set_descriptors,
    ]
  }
}

resource "aws_waf_rule" "whitelist" {
  depends_on = [aws_waf_ipset.whitelist]
  count = local.is_whitelist_enabled
  name = "${var.waf_prefix}-whitelist"
  metric_name = replace("${var.waf_prefix}whitelistWafRule", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_ipset.whitelist[0].id
    negated = false
    type = "IPMatch"
  }
}
