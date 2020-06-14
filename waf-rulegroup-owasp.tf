
## WAF Rule Groups
/**/
locals {
  owasp_rules_tmp = distinct([
    local.is_owasp_auth_tokens_enabled == 1 ?
      {
        action    = var.rule_owasp_auth_tokens_action,
        priority  = var.rule_owasp_auth_tokens_priority,
        id        = aws_waf_rule.owasp_auth_tokens.0.id
      } : {},
    local.is_owasp_csrf_enabled == 1 ?
      {
        action    = var.rule_owasp_csrf_action,
        priority  = var.rule_owasp_csrf_priority,
        id        = aws_waf_rule.owasp_csrf.0.id
      } : {},
    local.is_owasp_injection_sql_enabled == 1 ?
      {
        action    = var.rule_owasp_injection_sql_action,
        priority  = var.rule_owasp_injection_sql_priority,
        id        = aws_waf_rule.owasp_injection_sql.0.id
      } : {},
    local.is_owasp_path_traversal_enabled == 1 ?
      {
        action    = var.rule_owasp_path_traversal_action,
        priority  = var.rule_owasp_path_traversal_priority,
        id        = aws_waf_rule.owasp_path_traversal.0.id
      } : {},
    local.is_owasp_php_enabled == 1 ?
      {
        action    = var.rule_owasp_php_action,
        priority  = var.rule_owasp_php_priority,
        id        = aws_waf_rule.owasp_php.0.id
      } : {},
    local.is_owasp_size_restriction_enabled == 1 ?
      {
        action    = var.rule_owasp_size_restriction_action,
        priority  = var.rule_owasp_size_restriction_priority,
        id        = aws_waf_rule.owasp_size_restriction.0.id
      } : {},
    local.is_owasp_ssi_enabled == 1 ?
      {
        action    = var.rule_owasp_ssi_action,
        priority  = var.rule_owasp_ssi_priority,
        id        = aws_waf_rule.owasp_ssi.0.id
      } : {},
    local.is_owasp_xss_enabled == 1 ?
      {
        action    = var.rule_owasp_xss_action,
        priority  = var.rule_owasp_xss_priority,
        id        = aws_waf_rule.owasp_xss.0.id
      } : {},
  ])
  owasp_rules = setsubtract(local.owasp_rules_tmp, [{}])
}

output "group_owasp_rules" {
  value = local.owasp_rules
}

# Random ID Generator
resource "random_id" "this" {
  count = var.enabled ? "1" : "0"
  byte_length = "8"
  keepers = {
    target_scope = "global"
  }
}

resource "aws_waf_rule_group" "owasp_top_10" {
  depends_on = [
    aws_waf_rule.owasp_auth_tokens,
    aws_waf_rule.owasp_csrf,
    aws_waf_rule.owasp_injection_sql,
    aws_waf_rule.owasp_path_traversal,
    aws_waf_rule.owasp_php,
    aws_waf_rule.owasp_size_restriction,
    aws_waf_rule.owasp_ssi,
    aws_waf_rule.owasp_xss,
  ]
  count       = var.create_rule_group_owasp ? 1 : 0
  name        = format("%s-owasp-top-10-%s", lower(var.waf_prefix), random_id.this.0.hex)
  metric_name = format("%sOWASPTop10%s", lower(var.waf_prefix), random_id.this.0.hex)
  # TODO: add replace for invalid chars

  dynamic "activated_rule" {
    iterator = rule
    for_each = local.owasp_rules
    content {
      action {
        type = rule.value["action"]
      }
      priority = rule.value["priority"]
      rule_id  = rule.value["id"]
      type     = "REGULAR"
    }
  }
}
/**/
