/*
resource "aws_waf_rule_group" "example" {
  name        = "example"
  metric_name = "example"

  # list of rules
  activated_rule {
    action {
      type = "COUNT"
    }
    priority = 50
    rule_id  = "${aws_waf_rule.example.id}"
  }
}
/**/

## WAF Rule Groups

# type var.rule_csrf
locals {
  owasp_rules = [
    local.is_owasp_injection_sql_enabled ?
      {
        action    = var.rule_owasp_injection_sql_action,
        priority  = var.rule_owasp_injection_sql_priority,
        id        = aws_waf_rule.owasp_injection_sql.0.id
      } : {},
    #aws_waf_rule.owasp_auth_tokens.0.id
    #aws_waf_rule.owasp_csrf.0.id
    #aws_waf_rule.owasp_injection_aql.0.id
    #aws_waf_rule.owasp_path_traversal.0.id
    #aws_waf_rule.owasp_security_misconfig_php.0.id
    #aws_waf_rule.owasp_size_restriction.0.id
    #aws_waf_rule.owasp_ssi.0.id
    #aws_waf_rule.owasp_xss.0.id
  ]
}

resource "aws_waf_rule_group" "owasp_top_10" {
  depends_on = [
    "aws_waf_rule.owasp_auth_tokens",
    "aws_waf_rule.owasp_csrf",
    "aws_waf_rule.owasp_injection_sql",
    "aws_waf_rule.owasp_path_traversal",
    "aws_waf_rule.owasp_security_misconfig_php",
    "aws_waf_rule.owasp_size_restriction",
    "aws_waf_rule.owasp_ssi",
    "aws_waf_rule.owasp_xss",
  ]
  #detect_admin_access
  #rate_limit
  #country_of_origin_filter

  count = lower(var.create_rule_group) ? 1 : 0

  name        = "${format("%s-owasp-top-10-%s", lower(var.service_name), random_id.this.0.hex)}"
  metric_name = "${format("%sOWASPTop10%s", lower(var.service_name), random_id.this.0.hex)}"

  # dynamic loop
  #   action type, priority, id
  dynamic "activated_rule" {
    iterator = rule
    for_each =
    content {
      activated_rule {
        action {
          type = rule.value[action]
        }
      }
      priority = rule.value[priority]
      rule_id  = rule.value[id]
      type     = "REGULAR"
    }
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "1"
    rule_id  = "${aws_waf_rule.owasp_07_size_restriction_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "2"
    rule_id  = "${aws_waf_rule.owasp_02_auth_token_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "3"
    rule_id  = "${aws_waf_rule.owasp_01_sql_injection_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "4"
    rule_id  = "${aws_waf_rule.owasp_03_xss_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "5"
    rule_id  = "${aws_waf_rule.owasp_04_paths_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "6"
    rule_id  = "${aws_waf_rule.owasp_06_php_insecure_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "7"
    rule_id  = "${aws_waf_rule.owasp_08_csrf_rule.0.id}"
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = "BLOCK"
    }

    priority = "8"
    rule_id  = "${aws_waf_rule.owasp_09_server_side_include_rule.0.id}"
    type     = "REGULAR"
  }
}

/*
# From acl rule
# sql injection
dynamic "rules" {
  iterator = x
  for_each = local.is_sqli_enabled == 1 ? ["enabled"] : []
  content {
    action {
      type = var.rule_sqli
    }
    priority = var.rule_sqli_priority
    rule_id  = aws_waf_rule.mitigate_sqli[0].id
    type     = "REGULAR"
  }
}
/**/
