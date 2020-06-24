
# OWASP Size contraints
# size constraints
variable "rule_owasp_size_restriction_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_owasp_size_restriction_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 10
}
variable "rule_size_constraints_field_map" {
  type        = list(map(string))
  description = "A map of fields and their associated size constrant in bytes. (0-21474836480)"
  default = [
    {
      size = 4096
      type = "BODY"
    },
    {
      size = 4096
      type = "QUERY_STRING"
    },
    {
      size = 4096
      type = "URI"
    }
  ]
}
variable "rule_size_constraints_header_map" {
  type        = list(map(string))
  description = "A map of headers and their associated size constrant in bytes. (0-21474836480)"
  default = [
    {
      size = 4096
      type = "cookie"
    }
  ]
}
locals {
  # Determine if the Size Constraints rule is enabled
  is_owasp_size_restriction_enabled = var.enabled && contains(var.enable_actions, var.rule_owasp_size_restriction_action) ? 1 : 0
}

resource "aws_waf_rule" "owasp_size_restriction" {
  count       = local.is_owasp_size_restriction_enabled
  name        = "${var.waf_prefix}-restrict-sizes"
  metric_name = replace("${var.waf_prefix}restrictsizes", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_size_constraint_set.size_restrictions[0].id
    negated = false
    type    = "SizeConstraint"
  }
  tags = local.tags
}
resource "aws_waf_size_constraint_set" "size_restrictions" {
  count = local.is_owasp_size_restriction_enabled
  name  = "${var.waf_prefix}-generic-size-restrictions"
  dynamic "size_constraints" {
    iterator = x
    for_each = var.rule_size_constraints_field_map
    content {
      text_transformation = "NONE"
      comparison_operator = "GT"
      size                = x.value.size < 0 ? 0 : x.value.size > 21474836480 ? 21474836480 : x.value.size
      field_to_match {
        type = x.value.type
      }
    }
  }
  dynamic "size_constraints" {
    iterator = x
    for_each = var.rule_size_constraints_header_map
    content {
      text_transformation = "NONE"
      comparison_operator = "GT"
      size                = x.value.size < 0 ? 0 : x.value.size > 21474836480 ? 21474836480 : x.value.size
      field_to_match {
        type = "HEADER"
        data = x.value.type
      }
    }
  }
}
