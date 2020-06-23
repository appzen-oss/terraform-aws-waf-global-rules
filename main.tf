
locals {
  tags = {
    Environment = var.environment
  }
}

# Random ID Generator
resource "random_id" "this" {
  count = var.enabled ? "1" : "0"
  byte_length = "8"
  keepers = {
    target_scope = "global"
  }
}
