
# OWASP Admin access

variable "rule_owasp_admin_access_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_owasp_admin_access_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 100
}
variable "rule_admin_access_ipv4" {
  type        = list(string)
  description = "A whitelist of IPV4 cidr blocks that are permitted to access these paths."
  default     = []
}
variable "rule_admin_access_ipv6" {
  type        = list(string)
  description = "A whitelist of IPV6 cidr blocks that are permitted to access these paths."
  default     = []
}
variable "rule_admin_access_paths" {
  type        = list(string)
  description = "A black list of relative paths."
  default     = ["/admin"]
}
locals {
  # Determine if the Admin Access rule is enabled
  is_owasp_admin_access_enabled = var.enabled && contains(var.enable_actions, var.rule_owasp_admin_access_action) ? 1 : 0
}

resource "aws_waf_rule" "detect_admin_access" {
  count       = local.is_owasp_admin_access_enabled
  name        = "${var.waf_prefix}-generic-detect-admin-access"
  metric_name = replace("${var.waf_prefix}genericdetectadminaccess", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_ipset.admin_remote_ipset[0].id
    negated = true
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_byte_match_set.match_admin_url[0].id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_ipset" "admin_remote_ipset" {
  count = local.is_owasp_admin_access_enabled
  name  = "${var.waf_prefix}-generic-match-admin-remote-ip"
  dynamic "ip_set_descriptors" {
    iterator = x
    for_each = var.rule_admin_access_ipv4
    content {
      type  = "IPV4"
      value = x.value.value
    }
  }
  dynamic "ip_set_descriptors" {
    iterator = x
    for_each = var.rule_admin_access_ipv6
    content {
      type  = "IPV6"
      value = x.value.value
    }
  }
}
resource "aws_waf_byte_match_set" "match_admin_url" {
  count = local.is_owasp_admin_access_enabled
  name  = "${var.waf_prefix}-generic-match-admin-url"
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_admin_access_paths
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "STARTS_WITH"

      field_to_match {
        type = "URI"
      }
    }
  }
}
