
# WAF classic Web ACL limits
#   10 rules
#    1 rule group

module "waf" {
  source = "../.."
  waf_prefix = "test"
  rule_blacklist_action               = "COUNT"
  rule_country_of_origin_action       = "COUNT"
  #rule_owasp_admin_access_action      = "COUNT"
  #rule_owasp_auth_tokens_action       = "COUNT"
  rule_owasp_csrf_action              = "COUNT"
  rule_owasp_injection_sql_action     = "COUNT"
  rule_owasp_path_traversal_action    = "COUNT"
  #rule_owasp_php_action               = "COUNT"
  rule_owasp_size_restriction_action  = "COUNT"
  rule_owasp_ssi_action               = "COUNT"
  rule_owasp_xss_action               = "COUNT"
  rule_rate_limit_action              = "COUNT"
  rule_whitelist_action               = "COUNT"
}

output "group_owasp_rules" {
  value = module.waf.group_owasp_rules
}
output "web_acl_rules" {
  value = module.waf.web_acl_rules
}
