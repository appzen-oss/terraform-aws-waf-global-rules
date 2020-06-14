
variable "rule_owasp_xss_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_owasp_xss_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 50
}

variable "rule_xss_request_fields" {
  type        = list(string)
  description = "A list of fields in the request to look for XSS attacks."
  default     = ["BODY", "URI", "QUERY_STRING"]
}
variable "rule_xss_request_fields_transforms" {
  type        = list(string)
  description = "A list of text tranformations to perform on fields before looking for XSS attacks."
  default     = ["HTML_ENTITY_DECODE", "URL_DECODE"]
}
variable "rule_xss_request_headers" {
  type        = list(string)
  description = "A list of headers in the request to look for XSS attacks."
  default     = ["cookie"]
}
variable "rule_xss_request_headers_transforms" {
  type        = list(string)
  description = "A list of text tranformations to perform on headers before looking for XSS attacks."
  default     = ["HTML_ENTITY_DECODE", "URL_DECODE"]
}
locals {
  # Determine if the XSS rule is enabled
  is_owasp_xss_enabled = var.enabled && contains(var.enable_actions, var.rule_owasp_xss_action) ? 1 : 0
}

## OWASP Top 10 2017-A7, 2013-A3, 2010-A2, 2007-A1
## Cross-site scripting (XSS)

resource "aws_waf_rule" "owasp_xss" {
  count       = local.is_owasp_xss_enabled
  name        = "${var.waf_prefix}-generic-mitigate-xss"
  metric_name = replace("${var.waf_prefix}genericmitigatexss", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_xss_match_set.xss_match_set[0].id
    negated = false
    type    = "XssMatch"

  }
}

resource "aws_waf_xss_match_set" "xss_match_set" {
  count       = local.is_owasp_xss_enabled
  name  = "${var.waf_prefix}-generic-detect-xss"

  dynamic "xss_match_tuples" {
    iterator = request_field
    for_each = setproduct(var.rule_xss_request_fields_transforms, var.rule_xss_request_fields)
    content {
      text_transformation = request_field.value[0]
      field_to_match {
        type = request_field.value[1]
      }
    }
  }
  dynamic "xss_match_tuples" {
    iterator = request_header
    for_each = setproduct(var.rule_xss_request_headers_transforms, var.rule_xss_request_headers)
    content {
      text_transformation = request_header.value[0]
      field_to_match {
        type = "HEADER"
        data = request_header.value[1]
      }
    }
  }
}
