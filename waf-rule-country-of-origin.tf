
# Country of origin blacklist/whitelist

# country of origin
variable "rule_country_of_origin_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rule_country_of_origin_blacklist_or_whitelist" {
  type        = string
  description = "Set this as a blacklist or whitelist"
  default     = "blacklist"
}
variable "rule_country_of_origin_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 6
}
variable "rule_country_of_origin_set" {
  type        = list(string)
  description = "A list of country codes to block/allow."
  default     = ["BR","CN","HK","ID","NG","PK","RO","RU","TR","UA","VN"]
}


variable "rule_country_of_origin_paths" {
  type        = list(string)
  description = "A list of paths to include in the waf rule. ex: [\"/my/sensitive/path\",\"/another/path\"]"
  default     = ["/*"]
}

locals {
  # Determine if the Country of Origin rule is enabled
  is_country_of_origin_enabled = var.enabled && contains(var.enable_actions, var.rule_country_of_origin_action) ? 1 : 0
}

resource "aws_waf_rule" "country_of_origin" {
  count       = local.is_country_of_origin_enabled
  name        = "${var.waf_prefix}-generic-country-of-origin"
  metric_name = replace("${var.waf_prefix}genericcountryoforigin", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_geo_match_set.geo_match_set[0].id
    negated = var.rule_country_of_origin_blacklist_or_whitelist != "blacklist"
    type    = "GeoMatch"
  }
  predicates {
    data_id = aws_waf_byte_match_set.geo_match_url[0].id
    negated = false
    type    = "ByteMatch"
  }
  tags = local.tags
}

resource "aws_waf_geo_match_set" "geo_match_set" {
  count = local.is_country_of_origin_enabled
  name  = "${var.waf_prefix}-geo-match-set"

  dynamic "geo_match_constraint" {
    iterator = country
    for_each = var.rule_country_of_origin_set
    content {
      type  = "Country"
      value = country.value
    }
  }
}

resource "aws_waf_byte_match_set" "geo_match_url" {
  count = local.is_country_of_origin_enabled
  name  = "${var.waf_prefix}-geo-match-url"
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rule_country_of_origin_paths
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "STARTS_WITH"

      field_to_match {
        type = "URI"
      }
    }
  }
}
