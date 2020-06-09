
variable "rule_auth_tokens_black_list" {
  type        = list(string)
  description = "A black list of values to look for in the Authorization and Cookie header of request."
  default     = []
}

# OWASP Top 10 - 2017-A2
# Bad or Hijacked Authorization Tokens
# Matches patterns in the cookie or Authorization header
resource "aws_waf_rule" "detect_bad_auth_tokens" {
  name        = "${var.waf_prefix}-generic-detect-bad-auth-tokens"
  metric_name = replace("${var.waf_prefix}genericdetectbadauthtokens", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_byte_match_set.match_auth_tokens.id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_byte_match_set" "match_auth_tokens" {
  count = local.is_auth_tokens_enabled
  name  = "${var.waf_prefix}-generic-match-auth-tokens"

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_auth_tokens_black_list
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "ENDS_WITH"
      field_to_match {
        type = "HEADER"
        data = "authorization"
      }
    }
  }

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_auth_tokens_black_list
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "HEADER"
        data = "cookie"
      }
    }
  }
}
