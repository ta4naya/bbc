# Locals
locals {
  es_domain_name     = "es-${var.env_label}"
  es_custom_endpoint = "es.${replace(var.public_hosted_zone, "/[.]$/", "")}"
}

# Secrets
data "vault_kv_secret_v2" "elasticsearch" {
  mount = "kv"
  name  = "bdpa/aws/accounts/${var.aws_account_id}/elasticsearch"
}

# Policy documents
## CloudWatch access policy
data "aws_iam_policy_document" "es_cloudwatch_log_policy" {
  statement {
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream"
    ]

    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/aes/domains/${local.es_domain_name}/*:*"]

    principals {
      identifiers = ["es.amazonaws.com"]
      type        = "Service"
    }
  }
}

## ES domain assume role policy
data "aws_iam_policy_document" "es_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/cloudops"]
    }
  }
}

## Master-user/management assume role policy
data "aws_iam_policy_document" "master_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"

      values = [aws_cognito_identity_pool.kibana_identities.id]
    }

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"

      values = ["authenticated"]
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.es_ansible.arn]
    }

    condition {
      test     = "Bool"
      variable = "aws:ViaAWSService"

      values = ["false"]
    }

    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"

      values = [var.eip_inner_bastion_1_public_ip, var.eip_inner_bastion_2_public_ip]
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/cloudops"]
    }
  }
}

## Cognito's assume role policy on behalf of the authenticated users
data "aws_iam_policy_document" "cognito_assume_role_policy_auth" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"

      values = [aws_cognito_identity_pool.kibana_identities.id]
    }

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"

      values = ["authenticated"]
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/cloudops"]
    }
  }
}

## Cognito's assume role policy on behalf of the unauthenticated users
data "aws_iam_policy_document" "cognito_assume_role_policy_unauth" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"

      values = [aws_cognito_identity_pool.kibana_identities.id]
    }

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"

      values = ["unauthenticated"]
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/cloudops"]
    }
  }
}

## Cognito authorized user policy
data "aws_iam_policy_document" "cognito_idpool_auth_policy" {
  statement {
    actions = [
      "mobileanalytics:PutEvents",
      "cognito-sync:*",
      "cognito-identity:*"
    ]

    resources = ["*"]
  }
}

## Cognito unauthorized user policy
data "aws_iam_policy_document" "cognito_idpool_unauth_policy" {
  statement {
    actions = [
      "mobileanalytics:PutEvents",
      "cognito-sync:*"
    ]

    resources = ["*"]
  }
}

## Logstash assume role policy
data "aws_iam_policy_document" "logstash_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:role/cloudops"]
    }
  }
}

## Logstash domain access policy
data "aws_iam_policy_document" "logstash_domain_access_policy" {
  statement {
    actions = ["es:ESHttp*"]

    resources = ["arn:aws:es:${var.aws_region}:${var.aws_account_id}:domain/${local.es_domain_name}/*"]
  }
}

# EC2 user data script
data "template_file" "private" {
  template = file("templates/private.tpl")
  vars = {
    ec2_user = var.private_ec2_user
  }
}

# Security groups
resource "aws_security_group" "es" {
  name        = "elasticsearch"
  description = "Access to Elasticsearch"
  vpc_id      = var.vpc_id

  ingress {
    description = "Elasticsearch ingest from private subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description     = "Elasticsearch configuration from inner bastion"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [var.security_group_inner_bastion_id]
  }

  ingress {
    description     = "Kibana access from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [var.security_group_lb_id]
  }

  tags = {
    Name = "elasticsearch"
  }
}

resource "aws_security_group" "logstash" {
  name        = "logstash"
  description = "Access to Logstash"
  vpc_id      = var.vpc_id

  ingress {
    description = "Beat ingest from private and public subnets"
    from_port   = 5044
    to_port     = 5044
    protocol    = "tcp"
    cidr_blocks = [
      var.subnet_private_a_cidr,
      var.subnet_private_b_cidr,
      var.subnet_public_a_cidr,
      var.subnet_public_b_cidr
    ]
  }

  tags = {
    Name = "logstash"
  }
}

# Cognito
## User pool
resource "aws_cognito_user_pool" "kibana_access" {
  name                        = "kibana_access"
  mfa_configuration           = "OFF"
  # Trailing whitespace is on purpose
  sms_authentication_message  = "Your authentication code is {####}. "

  username_configuration {
    case_sensitive = false
  }

  schema {
    attribute_data_type      = "String"
    developer_only_attribute = false
    mutable                  = false
    name                     = "roles"
    required                 = false

    string_attribute_constraints {
      max_length = "2048"
      min_length = "0"
    }
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  ## Create Kibana master user and group
  ## At the time of writing, the AWS module doesn't support to create a user in the Cognito user pool
  ## See https://github.com/hashicorp/terraform-provider-aws/issues/4542 for details
  provisioner local-exec {
    command = "aws cognito-idp admin-create-user --user-pool-id ${aws_cognito_user_pool.kibana_access.id} --username ${data.vault_kv_secret_v2.elasticsearch.data["cognito_master_user_username"]} --user-attributes Name=email,Value=${data.vault_kv_secret_v2.elasticsearch.data["cognito_master_user_username"]}@${local.es_custom_endpoint} --temporary-password ${data.vault_kv_secret_v2.elasticsearch.data["cognito_master_user_password"]} --message-action SUPPRESS"

    environment = {
      AWS_DEFAULT_REGION = var.aws_region
    }
  }
  provisioner local-exec {
    command = "aws cognito-idp create-group --user-pool-id ${aws_cognito_user_pool.kibana_access.id} --group-name master-user-group --role-arn ${aws_iam_role.es_master_access.arn}"

    environment = {
      AWS_DEFAULT_REGION = var.aws_region
    }
  }

  provisioner local-exec {
    command = "aws cognito-idp admin-add-user-to-group --user-pool-id ${aws_cognito_user_pool.kibana_access.id} --username ${data.vault_kv_secret_v2.elasticsearch.data["cognito_master_user_username"]} --group-name master-user-group"

    environment = {
      AWS_DEFAULT_REGION = var.aws_region
    }
  }
}

## User pool domain (this is the reply URL for Azure AD)
resource "aws_cognito_user_pool_domain" "kibana_access" {
  domain       = "${var.env_owner}-kibana-${var.env_label}"
  user_pool_id = aws_cognito_user_pool.kibana_access.id

  depends_on = [aws_cognito_user_pool_domain.kibana_access]
}

## Cognito IdP for Azure AD (OpenID Connect)
resource "aws_cognito_identity_provider" "azure_ad" {
  user_pool_id  = aws_cognito_user_pool.kibana_access.id
  provider_name = "AzureAD"
  provider_type = "OIDC"

  provider_details = {
    client_id                     = var.oidc_client_id
    client_secret                 = data.vault_kv_secret_v2.elasticsearch.data["cognito_oidc_client_secret"]
    attributes_request_method     = "GET"
    authorize_scopes              = "openid profile email"
    oidc_issuer                   = var.oidc_issuer
    attributes_url_add_attributes = false
  }

  attribute_mapping = {
    name           = "name"
    email          = "preferred_username"
    username       = "sub"
  }

  depends_on = [aws_cognito_user_pool_domain.kibana_access]
}

## Cognito identity pool
resource "aws_cognito_identity_pool" "kibana_identities" {
  identity_pool_name               = "kibana_identities"
  allow_unauthenticated_identities = false

  # Ignore changes to IdP providers since it will get updated through the ES domain deployment
  # See https://github.com/hashicorp/terraform-provider-aws/issues/5557 for details
  lifecycle {
    ignore_changes = [cognito_identity_providers]
  }
}

## Attach default roles for Cognito identity pool
resource "aws_cognito_identity_pool_roles_attachment" "kibana_identities" {
  identity_pool_id = aws_cognito_identity_pool.kibana_identities.id

  roles = {
    "authenticated"   = aws_iam_role.es_default_auth.arn
    "unauthenticated" = aws_iam_role.es_default_unauth.arn
  }

  lifecycle {
    ignore_changes = [role_mapping]
  }

  depends_on = [
    aws_cognito_identity_pool.kibana_identities,
    aws_iam_role.es_default_auth,
    aws_iam_role.es_default_unauth
  ]
}

# Cognito user groups
resource "aws_cognito_user_group" "admin" {
  name         = "admin-group"
  user_pool_id = aws_cognito_user_pool.kibana_access.id
  role_arn     = aws_iam_role.es_admin_auth.arn
}

resource "aws_cognito_user_group" "poweruser" {
  name         = "poweruser-group"
  user_pool_id = aws_cognito_user_pool.kibana_access.id
  role_arn     = aws_iam_role.es_poweruser_auth.arn
}

resource "aws_cognito_user_group" "user" {
  name         = "user-group"
  user_pool_id = aws_cognito_user_pool.kibana_access.id
  role_arn     = aws_iam_role.es_user_auth.arn
}

# CloudWatch
## Log group
resource "aws_cloudwatch_log_group" "es_application_logs" {
  name = "/aws/aes/domains/${local.es_domain_name}/application-logs"
}

## Log policy
resource "aws_cloudwatch_log_resource_policy" "es_cloudwatch_log_policy" {
  policy_document = data.aws_iam_policy_document.es_cloudwatch_log_policy.json
  policy_name     = "AES-${local.es_domain_name}-logs"

  depends_on = [aws_cloudwatch_log_group.es_application_logs]
}

# IAM
## Service linked role for ES
resource "aws_iam_service_linked_role" "es" {
  aws_service_name = "es.amazonaws.com"
}

## Role gives ES the required permissions to configure the Cognito user and identity pools for Kibana authentication
resource "aws_iam_role" "es_cognito" {
  name               = "es-cognito"
  description        = "Amazon Elasticsearch role for Kibana authentication."
  assume_role_policy = data.aws_iam_policy_document.es_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "es_cognito" {
  role       = aws_iam_role.es_cognito.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonESCognitoAccess"

  depends_on = [aws_iam_role.es_cognito]
}

## Role for the master-user/management access
resource "aws_iam_role" "es_master_access" {
  name               = "es-master-access"
  description        = "Amazon Elasticsearch role for master-user/management access."
  assume_role_policy = data.aws_iam_policy_document.master_assume_role_policy.json
}

## Roles for the federated identities
resource "aws_iam_role" "es_default_auth" {
  name               = "es-default-auth"
  description        = "Amazon Elasticsearch default role for authenticated users."
  assume_role_policy = data.aws_iam_policy_document.cognito_assume_role_policy_auth.json
}

resource "aws_iam_role" "es_default_unauth" {
  name               = "es-default-unauth"
  description        = "Amazon Elasticsearch default role for unauthenticated users."
  assume_role_policy = data.aws_iam_policy_document.cognito_assume_role_policy_unauth.json
}

resource "aws_iam_role" "es_admin_auth" {
  name               = "es-admin-auth"
  description        = "Amazon Elasticsearch role for admins."
  assume_role_policy = data.aws_iam_policy_document.cognito_assume_role_policy_auth.json
}

resource "aws_iam_role" "es_poweruser_auth" {
  name               = "es-poweruser-auth"
  description        = "Amazon Elasticsearch role for power user."
  assume_role_policy = data.aws_iam_policy_document.cognito_assume_role_policy_auth.json
}

resource "aws_iam_role" "es_user_auth" {
  name               = "es-user-auth"
  description        = "Amazon Elasticsearch role for user."
  assume_role_policy = data.aws_iam_policy_document.cognito_assume_role_policy_auth.json
}

resource "aws_iam_role_policy" "es_default_auth" {
  name   = "es-default-auth"
  role   = aws_iam_role.es_default_auth.id
  policy = data.aws_iam_policy_document.cognito_idpool_auth_policy.json
}

resource "aws_iam_role_policy" "es_default_unauth" {
  name   = "es-default-unauth"
  role   = aws_iam_role.es_default_unauth.id
  policy = data.aws_iam_policy_document.cognito_idpool_unauth_policy.json
}

resource "aws_iam_role_policy" "es_admin_auth" {
  name   = "es-admin-auth"
  role   = aws_iam_role.es_admin_auth.id
  policy = data.aws_iam_policy_document.cognito_idpool_auth_policy.json
}

resource "aws_iam_role_policy" "es_poweruser_auth" {
  name   = "es-poweruser-auth"
  role   = aws_iam_role.es_poweruser_auth.id
  policy = data.aws_iam_policy_document.cognito_idpool_auth_policy.json
}

resource "aws_iam_role_policy" "es_user_auth" {
  name   = "es-user-auth"
  role   = aws_iam_role.es_user_auth.id
  policy = data.aws_iam_policy_document.cognito_idpool_auth_policy.json
}

## Roles for logstash access
resource "aws_iam_role" "es_logstash_access" {
  name               = "es-logstash-access"
  description        = "Amazon Elasticsearch role for logstash access."
  assume_role_policy = data.aws_iam_policy_document.logstash_assume_role_policy.json
}

resource "aws_iam_role_policy" "es_logstash_access" {
  name   = "es-logstash-access"
  role   = aws_iam_role.es_logstash_access.id
  policy = data.aws_iam_policy_document.logstash_domain_access_policy.json
}

## Instance profile for the logstash instances
resource "aws_iam_instance_profile" "logstash" {
  name = "logstash"
  role = aws_iam_role.es_logstash_access.id
}

## User for ansible access
resource "aws_iam_user" "es_ansible" {
  name = "es-ansible"
}

# Elasticsearch domain and access policy
resource "aws_elasticsearch_domain" "es" {
  domain_name           = local.es_domain_name
  elasticsearch_version = var.es_version

  cluster_config {
    instance_type            = var.es_data_instance_type
    instance_count           = var.es_data_instance_count
    dedicated_master_enabled = true
    dedicated_master_type    = var.es_master_instance_type
    dedicated_master_count   = var.es_master_instance_count
    zone_awareness_enabled   = true
    zone_awareness_config {
      availability_zone_count = 2
    }
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false

    master_user_options {
      master_user_arn = aws_iam_role.es_master_access.arn
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = var.es_ebs_volume_size
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
    custom_endpoint_enabled = true
    custom_endpoint = local.es_custom_endpoint
    custom_endpoint_certificate_arn = aws_acm_certificate_validation.es.certificate_arn
  }

  vpc_options {
    subnet_ids = [var.subnet_private_a_id, var.subnet_private_b_id]
    security_group_ids = [aws_security_group.es.id]
  }

  snapshot_options {
    automated_snapshot_start_hour = var.es_snapshot_start_hour
  }

  cognito_options {
    enabled          = true
    user_pool_id     = aws_cognito_user_pool.kibana_access.id
    identity_pool_id = aws_cognito_identity_pool.kibana_identities.id
    role_arn         = aws_iam_role.es_cognito.arn
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_application_logs.arn
    enabled                  = true
    log_type                 = "ES_APPLICATION_LOGS"
  }

  tags = {
    Domain = local.es_domain_name
  }

  depends_on = [
    aws_security_group.es,
    aws_iam_service_linked_role.es,
    aws_cognito_user_pool.kibana_access,
    aws_cognito_identity_pool.kibana_identities,
    aws_iam_role.es_cognito,
    aws_cloudwatch_log_group.es_application_logs
  ]
}

resource "aws_elasticsearch_domain_policy" "es" {
  domain_name = aws_elasticsearch_domain.es.domain_name

  access_policies = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "es:ESHttp*",
        "Principal": {
          "AWS": "*"
        },
        "Effect": "Allow",
        "Resource": "arn:aws:es:${var.aws_region}:${var.aws_account_id}:domain/${local.es_domain_name}/*"
      }
    ]
  }
  EOF

  depends_on = [aws_elasticsearch_domain.es]
}

# Logstash EC2 instances
resource "aws_instance" "logstash_1" {
  instance_type          = var.logstash_instance_type
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [
    var.security_group_private_id,
    aws_security_group.logstash.id
  ]
  subnet_id              = var.subnet_private_a_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = aws_iam_instance_profile.logstash.name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name       = "logstash-1"
    ScheduleV2 = var.scheduler_logstash_tag
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_instance" "logstash_2" {
  instance_type          = var.logstash_instance_type
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [
    var.security_group_private_id,
    aws_security_group.logstash.id
  ]
  subnet_id              = var.subnet_private_b_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = aws_iam_instance_profile.logstash.name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name       = "logstash-2"
    ScheduleV2 = var.scheduler_logstash_tag
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# Route53 records
resource "aws_route53_record" "logstash_1" {
  zone_id = var.private_zone_id
  name    = "logstash01"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.logstash_1.private_ip]
}

resource "aws_route53_record" "logstash_2" {
  zone_id = var.private_zone_id
  name    = "logstash02"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.logstash_2.private_ip]
}

resource "aws_route53_record" "es" {
  zone_id = var.public_zone_id
  name    = "es"
  type    = "A"

  alias {
    name                   = var.lb_dns_name
    zone_id                = var.lb_zone_id
    evaluate_target_health = true
  }
}

# ACM certificates and validation records
resource "aws_acm_certificate" "es" {
  domain_name       = "es.${replace(var.public_hosted_zone, "/[.]$/", "")}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "es_cert_validation" {
  name    = tolist(aws_acm_certificate.es.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.es.domain_validation_options)[0].resource_record_type
  zone_id = var.public_zone_id
  records = [tolist(aws_acm_certificate.es.domain_validation_options)[0].resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "es" {
  certificate_arn         = aws_acm_certificate.es.arn
  validation_record_fqdns = [aws_route53_record.es_cert_validation.fqdn]
}

# LB certificates
resource "aws_lb_listener_certificate" "es" {
  listener_arn    = var.ssl_listener_arn
  certificate_arn = aws_acm_certificate.es.arn
  depends_on      = [aws_acm_certificate_validation.es]
}

# LB target groups and attachments
resource "aws_lb_target_group" "es" {
  name        = local.es_domain_name
  target_type = "ip"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = var.vpc_id

  health_check {
    protocol = "HTTPS"
    path     = "/_dashboards"
    matcher  = 302
  }
}

data "aws_network_interfaces" "es" {
  filter {
    name   = "requester-id"
    values = ["amazon-elasticsearch"]
  }
}

data "aws_network_interface" "es" {
  for_each = toset(data.aws_network_interfaces.es.ids)

  id = each.value
}

resource "aws_lb_target_group_attachment" "es" {
  for_each = data.aws_network_interface.es

  target_group_arn = aws_lb_target_group.es.arn
  target_id        = each.value.private_ip
  port             = 443
}

# LB listener rules
data "aws_cognito_user_pool_clients" "es" {
  user_pool_id = aws_cognito_user_pool.kibana_access.id
}

resource "aws_lb_listener_rule" "es" {
  listener_arn = var.ssl_listener_arn

  action {
    type = "authenticate-cognito"

    authenticate_cognito {
      on_unauthenticated_request = "authenticate"
      scope                      = "openid"
      session_cookie_name        = "aws-elasticsearch"
      session_timeout            = 86400
      user_pool_arn              = aws_cognito_user_pool.kibana_access.arn
      # TODO: Make this idempotent
      user_pool_client_id        = tolist(data.aws_cognito_user_pool_clients.es.client_ids)[0]
      user_pool_domain           = aws_cognito_user_pool_domain.kibana_access.domain
    }
  }

  condition {
    host_header {
      values = ["es.${replace(var.public_hosted_zone, "/[.]$/", "")}"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.es.arn
  }
}
