
# OWASP PHP Security Misconfiguration

# php
variable "rule_php" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_php_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 70
}
variable "rule_php_insecure_uri_text_map" {
  type        = list(map(string))
  description = "A blacklist of text in a particular position within the URI of a request."
  default = [
    {
      text     = "php"
      position = "ENDS_WITH"
    },
    {
      text     = "/"
      position = "ENDS_WITH"
    },
  ]
}
variable "rule_php_insecure_query_string_parts" {
  type        = list(string)
  description = "A blacklist of text within the QUERYSTRING of a request."
  default = [
    "_ENV[",
    "_SERVER[",
    "allow_url_include=",
    "auto_append_file=",
    "auto_prepend_file=",
    "disable_functions=",
    "open_basedir=",
    "safe_mode="
  ]
}


resource "aws_waf_rule" "detect_php_insecure" {
  count       = local.is_php_enabled
  name        = "${var.waf_prefix}-generic-detect-php-insecure"
  metric_name = "${var.waf_prefix}genericdetectphpinsecure"
  predicates {
    data_id = aws_waf_byte_match_set.match_php_insecure_uri[0].id
    negated = false
    type    = "ByteMatch"
  }
  predicates {
    data_id = aws_waf_byte_match_set.match_php_insecure_var_refs[0].id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_waf_byte_match_set" "match_php_insecure_uri" {
  count = local.is_php_enabled
  name  = "${var.waf_prefix}-generic-match-php-insecure-uri"
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_php_insecure_uri_text_map
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value.text
      positional_constraint = x.value.position
      field_to_match {
        type = "URI"
      }
    }
  }
}
resource "aws_waf_byte_match_set" "match_php_insecure_var_refs" {
  count = local.is_php_enabled
  name  = "${var.waf_prefix}-generic-match-php-insecure-var-refs"
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_php_insecure_query_string_parts
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
