# Secrets
data "vault_kv_secret_v2" "icinga" {
  mount = "kv"
  name  = "bdpa/aws/accounts/${var.aws_account_id}/icinga"
}

# EC2 user data scripts
data "template_file" "private" {
  template = file("templates/private.tpl")
  vars = {
    ec2_user = var.private_ec2_user
  }
}

# Security groups
resource "aws_security_group" "icinga_master" {
  name        = "icinga-master"
  description = "Access to icinga master"
  vpc_id      = var.vpc_id

  tags = {
    Name = "icinga-master"
  }
}

resource "aws_security_group_rule" "icinga_master_ingress_api" {
  type              = "ingress"
  description       = "Icinga API access from private subnets"
  from_port         = 5665
  to_port           = 5665
  protocol          = "tcp"
  cidr_blocks       = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  security_group_id = aws_security_group.icinga_master.id
}

resource "aws_security_group_rule" "icinga_master_ingress_api_bek" {
  count = var.bayer_connect_managed ? 1 : 0

  type              = "ingress"
  description       = "Icinga API access from BEK network"
  from_port         = 5665
  to_port           = 5665
  protocol          = "tcp"
  cidr_blocks       = [var.cidr_bek_network]
  security_group_id = aws_security_group.icinga_master.id
}

resource "aws_security_group_rule" "icinga_master_ingress_alb" {
  type                     = "ingress"
  description              = "Icinga web access from ALB"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = var.security_group_lb_id
  security_group_id        = aws_security_group.icinga_master.id
}

resource "aws_security_group_rule" "icinga_master_ingress_icmp" {
  type              = "ingress"
  description       = "ICMP from Icinga master zone"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  self              = true
  security_group_id = aws_security_group.icinga_master.id
}

resource "aws_security_group_rule" "icinga_master_ingress_ssh" {
  type              = "ingress"
  description       = "SSH access from Icinga master zone"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.icinga_master.id
}

resource "aws_security_group_rule" "icinga_master_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.icinga_master.id
}

resource "aws_security_group" "icinga_satellite" {
  name        = "icinga-satellite"
  description = "Access to icinga satellite"
  vpc_id      = var.vpc_id

  tags = {
    Name = "icinga-satellite"
  }
}

resource "aws_security_group_rule" "icinga_satellite_ingress_api" {
  type              = "ingress"
  description       = "Icinga API access from private subnets"
  from_port         = 5665
  to_port           = 5665
  protocol          = "tcp"
  cidr_blocks       = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  security_group_id = aws_security_group.icinga_satellite.id
}

resource "aws_security_group_rule" "icinga_satellite_ingress_icmp" {
  type              = "ingress"
  description       = "ICMP from Icinga satellite zone"
  protocol          = "icmp"
  from_port         = -1
  to_port           = -1
  self              = true
  security_group_id = aws_security_group.icinga_satellite.id
}

resource "aws_security_group_rule" "icinga_satellite_ingress_ssh" {
  type              = "ingress"
  description       = "SSH access from Icinga satellite zone"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.icinga_satellite.id
}

resource "aws_security_group_rule" "icinga_satellite_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.icinga_satellite.id
}

# EC2 instances and volume attachments
resource "aws_instance" "icinga_1" {
  instance_type          = "t3.medium"
  ami                    = var.rockylinux8_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.icinga_master.id]
  subnet_id              = var.subnet_private_a_id
  user_data              = data.template_file.private.rendered

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "icinga-master-1"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_instance" "icinga_2" {
  instance_type          = "t3.medium"
  ami                    = var.rockylinux8_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.icinga_master.id]
  subnet_id              = var.subnet_private_b_id
  user_data              = data.template_file.private.rendered

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "icinga-master-2"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_instance" "icinga_3" {
  instance_type          = "t3.medium"
  ami                    = var.rockylinux8_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.icinga_satellite.id]
  subnet_id              = var.subnet_private_a_id
  user_data              = data.template_file.private.rendered

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "icinga-satellite-1"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_instance" "icinga_4" {
  instance_type          = "t3.medium"
  ami                    = var.rockylinux8_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.icinga_satellite.id]
  subnet_id              = var.subnet_private_b_id
  user_data              = data.template_file.private.rendered

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "icinga-satellite-2"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# Route53 records
resource "aws_route53_record" "icinga_1" {
  zone_id = var.private_zone_id
  name    = "icinga01"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.icinga_1.private_ip]
}

resource "aws_route53_record" "icinga_2" {
  zone_id = var.private_zone_id
  name    = "icinga02"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.icinga_2.private_ip]
}

resource "aws_route53_record" "icinga_3" {
  zone_id = var.private_zone_id
  name    = "icinga03"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.icinga_3.private_ip]
}

resource "aws_route53_record" "icinga_4" {
  zone_id = var.private_zone_id
  name    = "icinga04"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.icinga_4.private_ip]
}

resource "aws_route53_record" "icinga" {
  zone_id = var.public_zone_id
  name    = "icinga"
  type    = "A"

  alias {
    name                   = var.lb_dns_name
    zone_id                = var.lb_zone_id
    evaluate_target_health = true
  }
}

# ACM certificates and validation records
resource "aws_acm_certificate" "icinga" {
  domain_name       = "icinga.${replace(var.public_hosted_zone, "/[.]$/", "")}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "icinga_cert_validation" {
  name    = tolist(aws_acm_certificate.icinga.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.icinga.domain_validation_options)[0].resource_record_type
  zone_id = var.public_zone_id
  records = [tolist(aws_acm_certificate.icinga.domain_validation_options)[0].resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "icinga" {
  certificate_arn         = aws_acm_certificate.icinga.arn
  validation_record_fqdns = [aws_route53_record.icinga_cert_validation.fqdn]
}

# LB certificates
resource "aws_lb_listener_certificate" "icinga" {
  listener_arn    = var.ssl_listener_arn
  certificate_arn = aws_acm_certificate.icinga.arn
  depends_on      = [aws_acm_certificate_validation.icinga]
}

# LB target groups and attachments
resource "aws_lb_target_group" "icinga_web" {
  name        = "icinga-web-${var.env_label}"
  target_type = "instance"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id

  health_check {
    port     = 80
    protocol = "HTTP"
    path     = "/"
    matcher  = 200
  }

  stickiness {
    type            = "app_cookie"
    cookie_duration = 86400
    cookie_name     = "Icingaweb2"
  }
}

resource "aws_lb_target_group_attachment" "icinga_1_web" {
  target_group_arn = aws_lb_target_group.icinga_web.arn
  target_id        = aws_instance.icinga_1.id
}

resource "aws_lb_target_group_attachment" "icinga_2_web" {
  target_group_arn = aws_lb_target_group.icinga_web.arn
  target_id        = aws_instance.icinga_2.id
}

# LB listener rules
resource "aws_lb_listener_rule" "icinga" {
  listener_arn = var.ssl_listener_arn

  action {
    type = "authenticate-oidc"

    authenticate_oidc {
      on_unauthenticated_request = "authenticate"
      scope                      = "openid"
      session_cookie_name        = "icinga-web"
      session_timeout            = 86400
      authorization_endpoint     = "https://login.microsoftonline.com/fcb2b37b-5da0-466b-9b83-0014b67a7c78/oauth2/v2.0/authorize"
      client_id                  = "cfe988b3-08c4-4521-b85d-a88b211c6902"
      client_secret              = data.vault_kv_secret_v2.icinga.data["alb_oidc_client_secret"]
      issuer                     = "https://login.microsoftonline.com/fcb2b37b-5da0-466b-9b83-0014b67a7c78/v2.0"
      token_endpoint             = "https://login.microsoftonline.com/fcb2b37b-5da0-466b-9b83-0014b67a7c78/oauth2/v2.0/token"
      user_info_endpoint         = "https://graph.microsoft.com/oidc/userinfo"
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.icinga_web.arn
  }

  condition {
    host_header {
      values = ["icinga.${replace(var.public_hosted_zone, "/[.]$/", "")}"]
    }
  }
}

# RDS
resource "aws_rds_cluster" "icinga" {
  cluster_identifier     = "icinga-${var.env_label}"
  engine                 = "aurora-mysql"
  engine_mode            = "serverless"
  engine_version         = "5.7.mysql_aurora.2.08.3"
  database_name          = "icinga"
  master_username        = data.vault_kv_secret_v2.icinga.data["rds_master_user_username"]
  master_password        = data.vault_kv_secret_v2.icinga.data["rds_master_user_password"]
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [var.security_group_rds_mysql_id]
  enable_http_endpoint   = true

  scaling_configuration {
    min_capacity             = 1
    max_capacity             = 4
    auto_pause               = false
    # seconds_before_timeout   = 300
    seconds_until_auto_pause = 300
    timeout_action           = "RollbackCapacityChange"
  }
}
