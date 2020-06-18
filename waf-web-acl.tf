
variable "acl_default_action" {
  type        = string
  description = "Default action for Web ACL"
  default     = "ALLOW"
}


locals {
  acl_rules_tmp = distinct([
    local.is_blacklist_enabled == 1 ?
      {
        action    = var.rule_blacklist_action,
        priority  = var.rule_blacklist_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.blacklist.0.id
      } : {},
    local.is_country_of_origin_enabled == 1 ?
      {
        action    = var.rule_country_of_origin_action,
        priority  = var.rule_country_of_origin_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.country_of_origin.0.id
      } : {},
    local.is_owasp_admin_access_enabled == 1 ?
      {
        action    = var.rule_owasp_admin_access_action,
        priority  = var.rule_owasp_admin_access_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_admin_access.0.id
      } : {},
    local.is_owasp_auth_tokens_enabled == 1 ?
      {
        action    = var.rule_owasp_auth_tokens_action,
        priority  = var.rule_owasp_auth_tokens_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_auth_tokens.0.id
      } : {},
    local.is_owasp_csrf_enabled == 1 ?
      {
        action    = var.rule_owasp_csrf_action,
        priority  = var.rule_owasp_csrf_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_csrf.0.id
      } : {},
    local.is_owasp_injection_sql_enabled == 1 ?
      {
        action    = var.rule_owasp_injection_sql_action,
        priority  = var.rule_owasp_injection_sql_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_injection_sql.0.id
      } : {},
    local.is_owasp_path_traversal_enabled == 1 ?
      {
        action    = var.rule_owasp_path_traversal_action,
        priority  = var.rule_owasp_path_traversal_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_path_traversal.0.id
      } : {},
    local.is_owasp_php_enabled == 1 ?
      {
        action    = var.rule_owasp_php_action,
        priority  = var.rule_owasp_php_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_php.0.id
      } : {},
    local.is_owasp_size_restriction_enabled == 1 ?
      {
        action    = var.rule_owasp_size_restriction_action,
        priority  = var.rule_owasp_size_restriction_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_size_restriction.0.id
      } : {},
    local.is_owasp_ssi_enabled == 1 ?
      {
        action    = var.rule_owasp_ssi_action,
        priority  = var.rule_owasp_ssi_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_ssi.0.id
      } : {},
    local.is_owasp_xss_enabled == 1 ?
      {
        action    = var.rule_owasp_xss_action,
        priority  = var.rule_owasp_xss_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.owasp_xss.0.id
      } : {},
    local.is_rate_limit_enabled == 1 ?
      {
        action    = var.rule_rate_limit_action,
        priority  = var.rule_rate_limit_priority,
        type      = "RATE_BASED",
        id        = aws_waf_rate_based_rule.rate_limit.0.id
      } : {},
    local.is_whitelist_enabled == 1 ?
      {
        action    = var.rule_whitelist_action,
        priority  = var.rule_whitelist_priority,
        type      = "REGULAR",
        id        = aws_waf_rule.whitelist.0.id
      } : {},
  ])
  acl_rules = setsubtract(local.acl_rules_tmp, [{}])
}

  #name        = format("%s-owasp-top-10-%s", lower(var.waf_prefix), random_id.this.0.hex)
  #metric_name = format("%sOWASPTop10%s", lower(var.waf_prefix), random_id.this.0.hex)
  ## TODO: add replace for invalid chars

resource "aws_waf_web_acl" "waf_acl" {
  depends_on = [
    aws_waf_rate_based_rule.rate_limit,
    aws_waf_rule.blacklist,
    aws_waf_rule.country_of_origin,
    aws_waf_rule.owasp_admin_access,
    aws_waf_rule.owasp_auth_tokens,
    aws_waf_rule.owasp_csrf,
    aws_waf_rule.owasp_injection_sql,
    aws_waf_rule.owasp_path_traversal,
    aws_waf_rule.owasp_php,
    aws_waf_rule.owasp_size_restriction,
    aws_waf_rule.owasp_ssi,
    aws_waf_rule.owasp_xss,
    aws_waf_rule.whitelist,
  ]
  count       = var.enabled ? 1 : 0
  name        = "${var.waf_prefix}-generic-acl"
  metric_name = "${var.waf_prefix}genericacl"
  ## Dynamic block to allow optional configuration of logging_configuration
  #dynamic "logging_configuration" {
  #  iterator = x
  #  for_each = aws_kinesis_firehose_delivery_stream.log_stream[*].arn
  #  content {
  #    log_destination = x.value
  #  }
  #}

  default_action {
    type = var.acl_default_action
  }

  dynamic "rules" {
    iterator = rule
    for_each = local.acl_rules
    content {
      action {
        type = rule.value["action"]
      }
      priority = rule.value["priority"]
      rule_id  = rule.value["id"]
      type     = rule.value["type"]
    }
  }
}

/**/
