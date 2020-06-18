
output "group_owasp_rules" {
  description = "Enabled OWASP rules"
  value = local.owasp_rules
}
output "web_acl_rules" {
  description = "Enabled Web ACL rules"
  value = local.acl_rules
}
