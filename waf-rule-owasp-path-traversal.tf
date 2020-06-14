
# OWASP Path Traversal, rfi, lfi
# rfi lfi - path traversal
variable "rule_owasp_path_traversal_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_owasp_path_traversal_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 60
}
variable "rule_rfi_lfi_querystring" {
  type        = list(string)
  description = "A list of values to look for traversal attacks in the request querystring."
  default     = ["://", "../"]
}
variable "rule_rfi_lfi_uri" {
  type        = list(string)
  description = "A list of values to look for traversal attacks in the request URI."
  default     = ["://", "../"]
}
locals {
  # Determine if the RFI/LFI rule is enabled
  is_owasp_path_traversal_enabled = var.enabled && contains(var.enable_actions, var.rule_owasp_path_traversal_action) ? 1 : 0
}

resource "aws_waf_rule" "owasp_path_traversal" {
  count       = local.is_owasp_path_traversal_enabled
  name        = "${var.waf_prefix}-generic-detect-rfi-lfi-traversal"
  metric_name = replace("${var.waf_prefix}genericdetectrfilfitraversal", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_byte_match_set.match_rfi_lfi_traversal[0].id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_byte_match_set" "match_rfi_lfi_traversal" {
  count = local.is_owasp_path_traversal_enabled
  name  = "${var.waf_prefix}-generic-match-rfi-lfi-traversal"

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_rfi_lfi_querystring
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_rfi_lfi_querystring
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_rfi_lfi_uri
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_rfi_lfi_uri
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
}
