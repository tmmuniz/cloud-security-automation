locals {
  common_tags = {
    Environment = var.environment
    Project     = var.project_name
    Owner       = var.owner
  }

  name_prefix       = "${var.project_name}-${var.environment}"
  ansible_role_name = regex("[^/]+$", var.ansible_role_arn)
  prowler_role_name = regex("[^/]+$", var.prowler_role_arn)
}