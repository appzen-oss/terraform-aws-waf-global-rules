
# OWASP SSI

variable "rule_ssi" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_ssi_priority" {
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

resource "aws_waf_rule" "detect_ssi" {
  count       = local.is_ssi_enabled
  name        = "${var.waf_prefix}-generic-detect-ssi"
  metric_name = "${var.waf_prefix}genericdetectssi"
  predicates {
    data_id = aws_waf_byte_match_set.match_ssi[0].id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_byte_match_set" "match_ssi" {
  count = local.is_ssi_enabled
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
