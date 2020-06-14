
# OWASP SSI
# Server Side Includes

variable "rule_owasp_ssi_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_owasp_ssi_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 90
}
variable "rule_ssi_file_extensions" {
  type        = list(string)
  description = "A blacklist of file extensions within the URI of a request."
  default     = [".bak", ".backup", ".cfg", ".conf", ".config", ".ini", ".log"]
}
variable "rule_ssi_paths" {
  type        = list(string)
  description = "A blacklist of relative paths within the URI of a request."
  default     = ["/includes"]
}
locals {
  # Determine if the SSI rule is enabled
  is_owasp_ssi_enabled = var.enabled && contains(var.enable_actions, var.rule_owasp_ssi_action) ? 1 : 0
}

resource "aws_waf_rule" "owasp_ssi" {
  count       = local.is_owasp_ssi_enabled
  name        = "${var.waf_prefix}-generic-detect-ssi"
  metric_name = replace("${var.waf_prefix}genericdetectssi", "/[^0-9A-Za-z]/", "")
  predicates {
    data_id = aws_waf_byte_match_set.match_ssi[0].id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_byte_match_set" "match_ssi" {
  count = local.is_owasp_ssi_enabled
  name  = "${var.waf_prefix}-generic-match-ssi"
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_ssi_file_extensions
    content {
      text_transformation   = "LOWERCASE"
      target_string         = lower(x.value)
      positional_constraint = "ENDS_WITH"
      field_to_match {
        type = "URI"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_ssi_paths
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
