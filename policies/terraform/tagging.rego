package terraform.tagging

import future.keywords.in

REQUIRED_TAGS := {"Environment", "Team", "CostCenter", "Owner"}

TAGGABLE_RESOURCES := {
    "aws_instance",
    "aws_s3_bucket",
    "aws_rds_instance",
    "aws_lambda_function",
    "aws_eks_cluster",
    "aws_elasticache_replication_group",
    "aws_dynamodb_table",
    "aws_sqs_queue",
    "aws_sns_topic",
    "aws_ecs_service",
}

deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type in TAGGABLE_RESOURCES
    required_tag := REQUIRED_TAGS[_]
    not resource.values.tags[required_tag]
    msg := sprintf(
        "Resource '%s' (type: %s) is missing required tag '%s'",
        [resource.name, resource.type, required_tag]
    )
}

# Validate Environment tag value
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type in TAGGABLE_RESOURCES
    env := resource.values.tags.Environment
    not env in {"dev", "staging", "prod", "sandbox"}
    msg := sprintf(
        "Resource '%s' has invalid Environment tag '%s' (must be: dev, staging, prod, sandbox)",
        [resource.name, env]
    )
}

# Validate CostCenter tag format (must be alphanumeric, e.g. CC-1234)
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type in TAGGABLE_RESOURCES
    cc := resource.values.tags.CostCenter
    not regex.match(`^CC-\d{4,6}$`, cc)
    msg := sprintf(
        "Resource '%s' has invalid CostCenter tag '%s' (must match CC-NNNN format)",
        [resource.name, cc]
    )
}

# Warn on missing recommended tags
warn[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type in TAGGABLE_RESOURCES
    not resource.values.tags.Project
    msg := sprintf("Resource '%s' is missing recommended tag 'Project'", [resource.name])
}

warn[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type in TAGGABLE_RESOURCES
    not resource.values.tags.ManagedBy
    msg := sprintf("Resource '%s' is missing recommended tag 'ManagedBy' (e.g. terraform, cdk)", [resource.name])
}

# _r 20260605134508-2f457b14
