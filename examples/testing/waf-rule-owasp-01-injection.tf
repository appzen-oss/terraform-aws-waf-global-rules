# Variables
#   waf_prefix,
variable "waf_prefix" {
  type        = string
  description = "A prefix to use for all named resources."
  default     = "testy"
}

## OWASP Top 10 A1
## SQL Injection Attacks
## Matches attempted SQL injection patterns (controlled by variables) in request
##    In fields: BODY, QUERY_STRING, URI
##    In headers: authorization, cookie

# TODO: Add count to make optional? By rule, entire module, both?
#enable_rule_sql_injection
variable "rule_sqli_request_fields" {
  type        = list(string)
  description = "A list of fields in the request to look for SQL injection attacks."
  default     = ["BODY", "QUERY_STRING", "URI"]
}
variable "rule_sqli_request_fields_transforms" {
  type        = list(string)
  description = "A list of text tranformations to perform on fields before looking for SQL injection attacks."
  default     = ["HTML_ENTITY_DECODE", "URL_DECODE"]
}
variable "rule_sqli_request_headers" {
  type        = list(string)
  description = "A list of headers in a request to look for SQL injection attacks."
  default     = ["cookie", "authorization"]
  #default     = ["Authorization", "cookie"]
}
variable "rule_sqli_request_headers_transforms" {
  type        = list(string)
  description = "A list of text tranformations to perform on headers before looking for SQL injection attacks."
  default     = ["HTML_ENTITY_DECODE", "URL_DECODE"]
}

resource aws_waf_rule mitigate_sqli {
  name        = "${var.waf_prefix}-generic-mitigate-sqli"
  metric_name = replace("${var.waf_prefix}genericmitigatesqli", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_sql_injection_match_set.sql_injection_match_set.id
    negated = false
    type    = "SqlInjectionMatch"
  }
}

resource aws_waf_sql_injection_match_set sql_injection_match_set {
  name = "${var.waf_prefix}-generic-detect-sqli"
  dynamic "sql_injection_match_tuples" {
    iterator = request_field
    for_each = setproduct(var.rule_sqli_request_fields_transforms, var.rule_sqli_request_fields)
    content {
      text_transformation = request_field.value[0]
      field_to_match {
        type = request_field.value[1]
      }
    }
  }
  dynamic "sql_injection_match_tuples" {
    iterator = request_header
    for_each = setproduct(var.rule_sqli_request_headers_transforms, var.rule_sqli_request_headers)
    content {
      text_transformation = request_header.value[0]
      field_to_match {
        type = "HEADER"
        data = request_header.value[1]
      }
    }
  }
}
