package terraform.encryption

import future.keywords.in

# Deny S3 buckets without server-side encryption
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_s3_bucket"
    not _has_sse(resource)
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [resource.name])
}

_has_sse(resource) {
    resource.values.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].sse_algorithm
}

# Deny unencrypted RDS instances
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_rds_instance"
    resource.values.storage_encrypted != true
    msg := sprintf("RDS instance '%s' must have storage_encrypted = true", [resource.name])
}

# Deny unencrypted EBS volumes
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_ebs_volume"
    resource.values.encrypted != true
    msg := sprintf("EBS volume '%s' must have encrypted = true", [resource.name])
}

# Deny unencrypted EBS root volumes on EC2
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_instance"
    block := resource.values.root_block_device[_]
    block.encrypted != true
    msg := sprintf("EC2 instance '%s' root block device must be encrypted", [resource.name])
}

# Deny SQS queues without KMS encryption
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_sqs_queue"
    not resource.values.kms_master_key_id
    msg := sprintf("SQS queue '%s' must have kms_master_key_id set for encryption at rest", [resource.name])
}

# Deny DynamoDB tables without encryption
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_dynamodb_table"
    server_side_encryption := resource.values.server_side_encryption[_]
    server_side_encryption.enabled != true
    msg := sprintf("DynamoDB table '%s' must have server_side_encryption enabled", [resource.name])
}

# Deny ElastiCache without at-rest encryption
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_elasticache_replication_group"
    resource.values.at_rest_encryption_enabled != true
    msg := sprintf("ElastiCache replication group '%s' must have at_rest_encryption_enabled = true", [resource.name])
}

# _r 20260601101215-658cb623
