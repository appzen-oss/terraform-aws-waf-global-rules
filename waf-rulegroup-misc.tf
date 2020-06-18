
# Test adding group into group
# group generic-all = misc + owasp
/*
## WAF Rule Groups
locals {
  misc_rules_tmp = distinct([
    local.is_country_of_origin_enabled == 1 ?
      {
        action    = var.rule_country_of_origin_action,
        priority  = var.rule_country_of_origin_priority,
        id        = aws_waf_rule.country_of_origin.0.id
      } : {},
    local.is_rate_limit_enabled == 1 ?
      {
        action    = var.rule_rate_limit_action,
        priority  = var.rule_rate_limit_priority,
        id        = aws_waf_rule.rate_limit.0.id
      } : {},
  ])
  misc_rules = setsubtract(local.misc_rules_tmp, [{}])
}
/**/
