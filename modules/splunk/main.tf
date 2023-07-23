# EC2 user data script
data "template_file" "private" {
  template = "${file("templates/private.tpl")}"
  vars = {
    ec2_user = var.private_ec2_user
  }
}

# SmartStore S3 bucket
resource "aws_s3_bucket" "splunk_remotestore" {
  bucket = "splunk-remotestore-${var.aws_account_id}-${var.aws_region}"
  acl    = "private"

  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:*"
        ],
        "Effect": "Deny",
        "Resource": [
          "arn:aws:s3:::splunk-remotestore-${var.aws_account_id}-${var.aws_region}",
          "arn:aws:s3:::splunk-remotestore-${var.aws_account_id}-${var.aws_region}/*"
        ],
        "Principal": "*",
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  }
  EOF
}

resource "aws_s3_bucket_public_access_block" "splunk_remotestore" {
  bucket = "splunk-remotestore-${var.aws_account_id}-${var.aws_region}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.splunk_remotestore]
}

# IAM role and instance profile
resource "aws_iam_role_policy" "splunk_indexer" {
  name = "splunk-indexer"
  role = aws_iam_role.splunk_indexer.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:ListBucket"
        ],
        "Effect": "Allow",
        "Resource": "${var.bucket_private_files}"
      },
      {
        "Action": [
          "s3:ReadObject",
          "s3:GetObject"
        ],
        "Effect": "Allow",
        "Resource": "${var.bucket_private_files}/*"
      },
      {
        "Action": [
          "s3:ListBucket"
        ],
        "Effect": "Allow",
        "Resource": "${aws_s3_bucket.splunk_remotestore.arn}"
      },
      {
        "Action": [
          "s3:*Object"
        ],
        "Effect": "Allow",
        "Resource": "${aws_s3_bucket.splunk_remotestore.arn}/*"
      }
    ]
  }
  EOF

  depends_on = [aws_s3_bucket.splunk_remotestore]
}

resource "aws_iam_role" "splunk_indexer" {
  name = "splunk-indexer"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}

resource "aws_iam_instance_profile" "splunk" {
  name       = "splunk"
  role       = aws_iam_role.splunk_indexer.name
  depends_on = [aws_iam_role.splunk_indexer]
}

# Security groups (https://docs.splunk.com/Documentation/Splunk/latest/InheritedDeployment/Ports)
resource "aws_security_group" "splunk_indexer" {
  name        = "splunk-indexer"
  description = "Access to splunk indexer"
  vpc_id      = var.vpc_id

  ingress {
    description = "Splunk HTTP event collector from private subnets"
    from_port   = 8088
    to_port     = 8088
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description = "Splunk management from private subnets"
    from_port   = 8089
    to_port     = 8089
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description = "Splunk index replication from private subnets"
    from_port   = 9887
    to_port     = 9888
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description = "Splunk data receiver from private subnets"
    from_port   = 9997
    to_port     = 9998
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "splunk-indexer"
  }
}

resource "aws_security_group" "splunk_searchhead" {
  name        = "splunk-searchhead"
  description = "Access to splunk search head"
  vpc_id      = var.vpc_id

  ingress {
    description = "Splunk web from public subnets"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [var.subnet_public_a_cidr, var.subnet_public_b_cidr]
  }

  ingress {
    description = "Splunk management from private subnets"
    from_port   = 8089
    to_port     = 8089
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "splunk-searchhead"
  }
}

resource "aws_security_group" "splunk_licensemaster" {
  name        = "splunk-licensemaster"
  description = "Access to splunk license master"
  vpc_id      = var.vpc_id

  ingress {
    description = "Splunk management from private subnets"
    from_port   = 8089
    to_port     = 8089
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "splunk-licensemaster"
  }
}

resource "aws_security_group" "splunk_clustermaster" {
  name        = "splunk-clustermaster"
  description = "Access to splunk cluster master"
  vpc_id      = var.vpc_id

  ingress {
    description = "Splunk web from public subnets"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [var.subnet_public_a_cidr, var.subnet_public_b_cidr]
  }

  ingress {
    description = "Splunk management from private subnets"
    from_port   = 8089
    to_port     = 8089
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "splunk-clustermaster"
  }
}

# EC2 instances and volume attachments
resource "aws_instance" "splunk_1" {
  instance_type          = "t3.xlarge"
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.splunk_indexer.id]
  subnet_id              = var.subnet_private_a_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = aws_iam_instance_profile.splunk.name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "splunk-idx-1"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ebs_volume" "splunk_1_config" {
  availability_zone = aws_instance.splunk_1.availability_zone
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_1.tags["Name"]}-config"
  }
}

resource "aws_ebs_volume" "splunk_1_data" {
  availability_zone = aws_instance.splunk_1.availability_zone
  size              = 500
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_1.tags["Name"]}-data"
  }
}

resource "aws_volume_attachment" "splunk_1_config" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.splunk_1_config.id
  instance_id = aws_instance.splunk_1.id
}

resource "aws_volume_attachment" "splunk_1_data" {
  device_name = "/dev/sdc"
  volume_id   = aws_ebs_volume.splunk_1_data.id
  instance_id = aws_instance.splunk_1.id
}

resource "aws_instance" "splunk_2" {
  instance_type          = "t3.xlarge"
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.splunk_indexer.id]
  subnet_id              = var.subnet_private_b_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = aws_iam_instance_profile.splunk.name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "splunk-idx-2"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ebs_volume" "splunk_2_config" {
  availability_zone = aws_instance.splunk_2.availability_zone
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_2.tags["Name"]}-config"
  }
}

resource "aws_ebs_volume" "splunk_2_data" {
  availability_zone = aws_instance.splunk_2.availability_zone
  size              = 500
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_2.tags["Name"]}-data"
  }
}

resource "aws_volume_attachment" "splunk_2_config" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.splunk_2_config.id
  instance_id = aws_instance.splunk_2.id
}

resource "aws_volume_attachment" "splunk_2_data" {
  device_name = "/dev/sdc"
  volume_id   = aws_ebs_volume.splunk_2_data.id
  instance_id = aws_instance.splunk_2.id
}

resource "aws_instance" "splunk_3" {
  instance_type          = "t3.xlarge"
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.splunk_indexer.id]
  subnet_id              = var.subnet_private_a_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = aws_iam_instance_profile.splunk.name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "splunk-idx-3"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ebs_volume" "splunk_3_config" {
  availability_zone = aws_instance.splunk_3.availability_zone
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_3.tags["Name"]}-config"
  }
}

resource "aws_ebs_volume" "splunk_3_data" {
  availability_zone = aws_instance.splunk_3.availability_zone
  size              = 500
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_3.tags["Name"]}-data"
  }
}

resource "aws_volume_attachment" "splunk_3_config" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.splunk_3_config.id
  instance_id = aws_instance.splunk_3.id
}

resource "aws_volume_attachment" "splunk_3_data" {
  device_name = "/dev/sdc"
  volume_id   = aws_ebs_volume.splunk_3_data.id
  instance_id = aws_instance.splunk_3.id
}

resource "aws_instance" "splunk_4" {
  instance_type          = "t3.large"
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.splunk_searchhead.id]
  subnet_id              = var.subnet_private_a_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = var.profile_private_name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "splunk-sh-1"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ebs_volume" "splunk_4_config" {
  availability_zone = aws_instance.splunk_4.availability_zone
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_4.tags["Name"]}-config"
  }
}

resource "aws_ebs_volume" "splunk_4_data" {
  availability_zone = aws_instance.splunk_4.availability_zone
  size              = 100
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_4.tags["Name"]}-data"
  }
}

resource "aws_volume_attachment" "splunk_4_config" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.splunk_4_config.id
  instance_id = aws_instance.splunk_4.id
}

resource "aws_volume_attachment" "splunk_4_data" {
  device_name = "/dev/sdc"
  volume_id   = aws_ebs_volume.splunk_4_data.id
  instance_id = aws_instance.splunk_4.id
}

resource "aws_instance" "splunk_5" {
  instance_type          = "t3.large"
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [var.security_group_private_id, aws_security_group.splunk_searchhead.id]
  subnet_id              = var.subnet_private_b_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = var.profile_private_name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "splunk-sh-2"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ebs_volume" "splunk_5_config" {
  availability_zone = aws_instance.splunk_5.availability_zone
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_5.tags["Name"]}-config"
  }
}

resource "aws_ebs_volume" "splunk_5_data" {
  availability_zone = aws_instance.splunk_5.availability_zone
  size              = 100
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_5.tags["Name"]}-data"
  }
}

resource "aws_volume_attachment" "splunk_5_config" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.splunk_5_config.id
  instance_id = aws_instance.splunk_5.id
}

resource "aws_volume_attachment" "splunk_5_data" {
  device_name = "/dev/sdc"
  volume_id   = aws_ebs_volume.splunk_5_data.id
  instance_id = aws_instance.splunk_5.id
}

resource "aws_instance" "splunk_6" {
  instance_type          = "t3.medium"
  ami                    = var.centos_ami_id
  key_name               = var.common_ssh_key_id
  vpc_security_group_ids = [
    var.security_group_private_id,
    aws_security_group.splunk_licensemaster.id,
    aws_security_group.splunk_clustermaster.id
  ]
  subnet_id              = var.subnet_private_b_id
  user_data              = data.template_file.private.rendered
  iam_instance_profile   = var.profile_private_name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name = "splunk-master"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_ebs_volume" "splunk_6_config" {
  availability_zone = aws_instance.splunk_6.availability_zone
  size              = 10
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_6.tags["Name"]}-config"
  }
}

resource "aws_ebs_volume" "splunk_6_data" {
  availability_zone = aws_instance.splunk_6.availability_zone
  size              = 100
  type              = "gp2"
  encrypted         = true

  tags = {
    Name = "${aws_instance.splunk_6.tags["Name"]}-data"
  }
}

resource "aws_volume_attachment" "splunk_6_config" {
  device_name = "/dev/sdb"
  volume_id   = aws_ebs_volume.splunk_6_config.id
  instance_id = aws_instance.splunk_6.id
}

resource "aws_volume_attachment" "splunk_6_data" {
  device_name = "/dev/sdc"
  volume_id   = aws_ebs_volume.splunk_6_data.id
  instance_id = aws_instance.splunk_6.id
}

# Route53 records
resource "aws_route53_record" "splunk_1" {
  zone_id = var.private_zone_id
  name    = "splunk01"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.splunk_1.private_ip}"]
}

resource "aws_route53_record" "splunk_2" {
  zone_id = var.private_zone_id
  name    = "splunk02"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.splunk_2.private_ip}"]
}

resource "aws_route53_record" "splunk_3" {
  zone_id = var.private_zone_id
  name    = "splunk03"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.splunk_3.private_ip}"]
}

resource "aws_route53_record" "splunk_4" {
  zone_id = var.private_zone_id
  name    = "splunk04"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.splunk_4.private_ip}"]
}

resource "aws_route53_record" "splunk_5" {
  zone_id = var.private_zone_id
  name    = "splunk05"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.splunk_5.private_ip}"]
}

resource "aws_route53_record" "splunk_6" {
  zone_id = var.private_zone_id
  name    = "splunk06"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.splunk_6.private_ip}"]
}

resource "aws_route53_record" "splunk" {
  zone_id = var.public_zone_id
  name    = "splunk"
  type    = "A"

  alias {
    name                   = var.lb_dns_name
    zone_id                = var.lb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "splunkmaster" {
  zone_id = var.public_zone_id
  name    = "splunkmaster"
  type    = "A"

  alias {
    name                   = var.lb_dns_name
    zone_id                = var.lb_zone_id
    evaluate_target_health = true
  }
}

# ACM certificates and validation records
resource "aws_acm_certificate" "splunk" {
  domain_name       = "splunk.${replace(var.public_hosted_zone, "/[.]$/", "")}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate" "splunkmaster" {
  domain_name       = "splunkmaster.${replace(var.public_hosted_zone, "/[.]$/", "")}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "splunk_cert_validation" {
  name    = tolist(aws_acm_certificate.splunk.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.splunk.domain_validation_options)[0].resource_record_type
  zone_id = var.public_zone_id
  records = [tolist(aws_acm_certificate.splunk.domain_validation_options)[0].resource_record_value]
  ttl     = 60
}

resource "aws_route53_record" "splunkmaster_cert_validation" {
  name    = tolist(aws_acm_certificate.splunkmaster.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.splunkmaster.domain_validation_options)[0].resource_record_type
  zone_id = var.public_zone_id
  records = [tolist(aws_acm_certificate.splunkmaster.domain_validation_options)[0].resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "splunk" {
  certificate_arn         = aws_acm_certificate.splunk.arn
  validation_record_fqdns = [aws_route53_record.splunk_cert_validation.fqdn]
}

resource "aws_acm_certificate_validation" "splunkmaster" {
  certificate_arn         = aws_acm_certificate.splunkmaster.arn
  validation_record_fqdns = [aws_route53_record.splunkmaster_cert_validation.fqdn]
}

# LB certificates
resource "aws_lb_listener_certificate" "splunk" {
  listener_arn    = var.ssl_listener_arn
  certificate_arn = aws_acm_certificate.splunk.arn
  depends_on      = [aws_acm_certificate_validation.splunk]
}

resource "aws_lb_listener_certificate" "splunkmaster" {
  listener_arn    = var.ssl_listener_arn
  certificate_arn = aws_acm_certificate.splunkmaster.arn
  depends_on      = [aws_acm_certificate_validation.splunkmaster]
}

# LB target groups and attachments (https://docs.splunk.com/Documentation/Splunk/latest/DistSearch/UseSHCwithloadbalancers)
resource "aws_lb_target_group" "splunk_web" {
  name     = "splunk-web"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  stickiness {
    type = "lb_cookie"
  }
}

resource "aws_lb_target_group" "splunkmaster_web" {
  name     = "splunkmaster-web"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  stickiness {
    type = "lb_cookie"
  }
}

resource "aws_lb_target_group_attachment" "splunk_4_web" {
  target_group_arn = aws_lb_target_group.splunk_web.arn
  target_id        = aws_instance.splunk_4.id
  port             = 8000
}

resource "aws_lb_target_group_attachment" "splunk_5_web" {
  target_group_arn = aws_lb_target_group.splunk_web.arn
  target_id        = aws_instance.splunk_5.id
  port             = 8000
}

resource "aws_lb_target_group_attachment" "splunk_6_web" {
  target_group_arn = aws_lb_target_group.splunkmaster_web.arn
  target_id        = aws_instance.splunk_6.id
  port             = 8000
}

# LB listener rules
resource "aws_lb_listener_rule" "splunk" {
  listener_arn = var.ssl_listener_arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.splunk_web.arn
  }

  condition {
    host_header {
      values = ["splunk.${replace(var.public_hosted_zone, "/[.]$/", "")}"]
    }
  }
}

resource "aws_lb_listener_rule" "splunkmaster" {
  listener_arn = var.ssl_listener_arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.splunkmaster_web.arn
  }

  condition {
    host_header {
      values = ["splunkmaster.${replace(var.public_hosted_zone, "/[.]$/", "")}"]
    }
  }
}
