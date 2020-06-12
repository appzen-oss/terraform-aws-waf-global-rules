
# OWASP Top 10 2013-A8, 2010-A5, 2007-A5
# Cross-Site Request Forgery (CSRF)

# csrf - cross site request forgery
variable "rule_csrf" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_csrf_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 80
}
variable "rule_csrf_header" {
  type        = string
  description = "The name of your CSRF token header."
  default     = "x-csrf-token"
}
variable "rule_csrf_size" {
  type        = number
  description = "The size of your CSRF token."
  default     = 36
}
locals {
  # Determine if the CSRF rule is enabled
  is_csrf_enabled = var.enabled && contains(var.enable_actions, var.rule_csrf) ? 1 : 0
}

resource "aws_waf_rule" "owasp_csrf" {
  count       = local.is_csrf_enabled
  name        = "${var.waf_prefix}-generic-enforce-csrf"
  metric_name = replace("${var.waf_prefix}genericenforcecsrf", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_byte_match_set.match_csrf_method[0].id
    negated = false
    type    = "ByteMatch"
  }

  predicates {
    data_id = aws_waf_size_constraint_set.csrf_token_set[0].id
    negated = true
    type    = "SizeConstraint"
  }
}
resource "aws_waf_byte_match_set" "match_csrf_method" {
  count = local.is_csrf_enabled
  name  = "${var.waf_prefix}-generic-match-csrf-method"
  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = "post"
    positional_constraint = "EXACTLY"

    field_to_match {
      type = "METHOD"
    }
  }
}
resource "aws_waf_size_constraint_set" "csrf_token_set" {
  count = local.is_csrf_enabled
  name  = "${var.waf_prefix}-generic-match-csrf-token"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "EQ"
    size                = var.rule_csrf_size

    field_to_match {
      type = "HEADER"
      data = var.rule_csrf_header
    }
  }
}
