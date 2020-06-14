
module "waf" {
  source = "../.."
  waf_prefix = "test"
  rule_owasp_auth_tokens_action       = "COUNT"
  rule_owasp_csrf_action              = "COUNT"
  rule_owasp_injection_sql_action     = "COUNT"
  rule_owasp_path_traversal_action    = "COUNT"
  rule_owasp_php_action               = "COUNT"
  rule_owasp_size_restriction_action  = "COUNT"
  rule_owasp_ssi_action               = "COUNT"
  rule_owasp_xss_action               = "COUNT"
}

output "group_owasp_rules" {
  value = module.waf.group_owasp_rules
}
