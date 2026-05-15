package terraform.security

import rego.v1

# Blocks Security Groups with SSH open to the internet
# Frameworks: CIS AWS 4.1, NIST AC-4, ISO 27001 A.13.1
deny contains msg if {
  resource := input.resource_changes[_]

  resource.type == "aws_security_group"

  ingress := resource.change.after.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.cidr_blocks[_] == "0.0.0.0/0"

  msg := "Security Group must not allow SSH access from 0.0.0.0/0"
}

# Blocks public S3 access (ACLs and policies)
# Frameworks: CIS AWS 2.1.x, NIST AC-3, ISO 27001 A.9.1
deny contains msg if {
  resource := input.resource_changes[_]

  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.block_public_acls == false

  msg := "S3 must block public ACLs"
}

deny contains msg if {
  resource := input.resource_changes[_]

  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.block_public_policy == false

  msg := "S3 must block public bucket policies"
}

deny contains msg if {
  resource := input.resource_changes[_]

  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.ignore_public_acls == false

  msg := "S3 must ignore public ACLs"
}

deny contains msg if {
  resource := input.resource_changes[_]

  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.restrict_public_buckets == false

  msg := "S3 must restrict public buckets"
}

# Requires S3 bucket encryption
# Frameworks: CIS AWS 2.3, NIST SC-12, ISO 27001 A.10.1
deny contains msg if {
  resource := input.resource_changes[_]

  resource.type == "aws_s3_bucket_server_side_encryption_configuration"

  not resource.change.after.rule

  msg := "S3 bucket must have server-side encryption configured"
}

# Required tags for EC2 and S3
# Frameworks: NIST CM-8, ISO 27001 A.8.1
is_required_tag_resource(resource) if {
  resource.type == "aws_instance"
}

is_required_tag_resource(resource) if {
  resource.type == "aws_s3_bucket"
}

deny contains msg if {
  resource := input.resource_changes[_]

  is_required_tag_resource(resource)

  required := {"Environment", "Project", "Owner"}

  tags := object.get(resource.change.after, "tags", {})

  missing := required - {tag | tags[tag]}

  count(missing) > 0

  msg := sprintf(
    "Resource %s is missing required tags: %v",
    [resource.address, missing]
  )
}

# EC2 root volume size limit (Free Tier control)
# Frameworks: Cost control (FinOps), NIST CM-7
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.actions[_] == "create"

  block := resource.change.after.root_block_device[_]
  block.volume_size > 30

  msg := sprintf("EC2 instance %s root volume exceeds 30 GB", [resource.address])
}

# EC2 root volume encryption
# Frameworks: CIS AWS 4.2, NIST SC-28, ISO 27001 A.10.1
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.actions[_] == "create"

  block := resource.change.after.root_block_device[_]
  block.encrypted == false

  msg := sprintf("EC2 instance %s must use an encrypted root volume", [resource.address])
}

# Restrict EC2 instance types to Free Tier
# Frameworks: Cost governance (FinOps)
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  resource.change.actions[_] == "create"

  not resource.change.after.instance_type in {"t2.micro", "t3.micro"}

  msg := sprintf("EC2 instance %s must use a Free Tier eligible instance type", [resource.address])
}

# Block HTTP exposure to the internet
# Frameworks: CIS AWS 4.1, NIST AC-4, ISO 27001 A.13.1
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  resource.change.actions[_] == "create"

  ingress := resource.change.after.ingress[_]
  ingress.from_port == 80
  cidr := ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg := sprintf("Security Group %s must not expose HTTP to 0.0.0.0/0", [resource.address])
}

# IAM PassRole wildcard restriction
# Frameworks: CIS AWS 1.22, NIST AC-6, ISO 27001 A.9.2
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  resource.change.actions[_] == "create"

  contains(resource.change.after.policy, "iam:PassRole")
  contains(resource.change.after.policy, "\"Resource\":\"*\"")

  msg := sprintf("IAM policy %s must not allow iam:PassRole on wildcard resources", [resource.address])
}

# CloudTrail must be enabled
# Frameworks: CIS AWS 3.1, NIST AU-2, ISO 27001 A.12.4
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"
  resource.change.actions[_] == "create"

  resource.change.after.is_logging == false

  msg := sprintf("CloudTrail %s must be enabled", [resource.address])
}
