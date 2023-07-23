# EC2 user data scripts
data "template_file" "inner_bastion" {
  template = file("templates/bastion.tpl")
  vars = {
    ec2_user         = var.inner_bastion_ec2_user
    sshd_port        = var.inner_bastion_sshd_port
    sshd_svcname     = var.inner_bastion_sshd_svcname
    files            = var.inner_bastion_files
    bucket_path      = var.inner_bastion_bucket_path
    bucket_name      = var.bucket_bastion_files
    bucket_object_id = var.inner_bastion_object_id
  }
}

# Security groups
resource "aws_security_group" "inner_bastion" {
  name        = "inner-bastion"
  description = "Access to inner bastion"
  vpc_id      = var.vpc_id

  # Central bastions
  dynamic "ingress" {
    for_each = var.jumpbox_ip_addr_list
    content {
      description = ""
      from_port   = var.inner_bastion_sshd_port
      to_port     = var.inner_bastion_sshd_port
      protocol    = "tcp"
      cidr_blocks = ["${ingress.value}/32"]
    }
  }

  # Self
  ingress {
    description = ""
    from_port   = var.inner_bastion_sshd_port
    to_port     = var.inner_bastion_sshd_port
    protocol    = "tcp"
    self        = true
  }

  # Route53 health checkers (global)
  # See https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/route-53-ip-addresses.html for details
  ingress {
    description = ""
    from_port   = var.inner_bastion_sshd_port
    to_port     = var.inner_bastion_sshd_port
    protocol    = "tcp"
    cidr_blocks = ["15.177.0.0/18"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "inner-bastion"
  }
}

resource "aws_security_group" "private" {
  name        = "private"
  description = "Access to private hosts"
  vpc_id      = var.vpc_id

  # Inner bastions
  ingress {
    from_port       = var.private_sshd_port
    to_port         = var.private_sshd_port
    protocol        = "tcp"
    security_groups = [aws_security_group.inner_bastion.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  depends_on = [aws_security_group.inner_bastion]

  tags = {
    Name = "private"
  }
}

# Cent OS 7 AMI (by CentOS.org)
# EOL June 30, 2024
data "aws_ami_ids" "centos" {
  owners = ["aws-marketplace"]
  filter {
    name   = "product-code"
    values = ["aw0evgkw8e5c1q413zgy5pjce"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Rocky Linux 8 AMI (by Rocky Linux)
# EOL May 31, 2029
data "aws_ami_ids" "rockylinux8" {
  owners = ["aws-marketplace"]
  filter {
    name   = "product-code"
    values = ["cotnnspjrsi38lfn8qo4ibnnm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Key pair
resource "aws_key_pair" "shygd" {
  key_name   = "shygd"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCjILEJkuAz7qBJcM4ZhxvT8wcKFAAi4hO5UY55ZY9doI4MQ2D7WKVuYbQjsbTe8LoA+4IiFY2yFuuy6asRKPkwi87pa/tAE36YdAx2N6vNhjHZ1Y5cSvkzmzwokY+tZvLj1HB9Hst7Za6uDcnLhjgnCf9ExpPJ55nkYBltrdW6fnAMOZQ+Mu3CU+0jdQ/Vev/j1cJjwOQCqLeACZR8+vDZ3TWfrjLV5AqeBPQCvpe254cSy4+qDfGm9NyZqgEQ2nZCHkN3sIz61gByC45pDwcq4BIwu94VvhQLGGSCcRa2ZKPOcF++XSVscC5fBO/cmwbqxR4iEkI9pVywXvfWERiHGyVrcr0cvyO+SGFIi9XrqJEep9VWbGjP0jX9CnyDw3RSHL9f1r7UNrinO5bUeKon/ZKgtHdulfJS0FVupmezf5oSevONdfmBrHjQIYGW5OND8OZE4jG88u/UVOA8bCF1/pbExVralQbXaL8WEbhUKwmz3pVZVlxTn+HCLfLS8eJG7BsslhTte8sH5gpv7uN455gHZTb7Gjz9R9W+MHxDBUF7oUdsF5voaZWO9c0/WRzi4rM8IPakoLCfAHBgC2DQkVrNpJlmEcKjWAO2/WOL/7c5XcIyD+rbYH5z7euFO199FB9odZHhrLg99OZIRo67Jb/POM3pRIkcSCl9kio9oQ== timo.bumke@bayer.com"
}

# EC2 instances
resource "aws_instance" "inner_bastion_1" {
  instance_type          = "t2.micro"
  ami                    = element(concat(data.aws_ami_ids.centos.ids, tolist([""])), 0)
  key_name               = aws_key_pair.shygd.id
  vpc_security_group_ids = [aws_security_group.inner_bastion.id]
  subnet_id              = var.subnet_public_a_id
  user_data              = data.template_file.inner_bastion.rendered
  iam_instance_profile   = var.profile_bastion_name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name       = "inner-bastion-1"
    ScheduleV2 = var.scheduler_bastion_tag
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_instance" "inner_bastion_2" {
  instance_type          = "t2.micro"
  ami                    = element(concat(data.aws_ami_ids.centos.ids, tolist([""])), 0)
  key_name               = aws_key_pair.shygd.id
  vpc_security_group_ids = [aws_security_group.inner_bastion.id]
  subnet_id              = var.subnet_public_b_id
  user_data              = data.template_file.inner_bastion.rendered
  iam_instance_profile   = var.profile_bastion_name

  root_block_device {
    volume_size = 100
    volume_type = "gp2"
    delete_on_termination = true
    encrypted = true
  }

  tags = {
    Name       = "inner-bastion-2"
    ScheduleV2 = var.scheduler_bastion_tag
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_eip" "inner_bastion_1" {
  vpc      = true
  instance = aws_instance.inner_bastion_1.id
}

resource "aws_eip" "inner_bastion_2" {
  vpc      = true
  instance = aws_instance.inner_bastion_2.id
}

# Route53 health checks
resource "aws_route53_health_check" "inner_bastion_1" {
  ip_address        = aws_eip.inner_bastion_1.public_ip
  port              = var.private_sshd_port
  type              = "TCP"
  failure_threshold = "5"
  request_interval  = "30"

  tags = {
    Name = "inner-bastion-1"
  }
}

resource "aws_route53_health_check" "inner_bastion_2" {
  ip_address        = aws_eip.inner_bastion_2.public_ip
  port              = var.private_sshd_port
  type              = "TCP"
  failure_threshold = "5"
  request_interval  = "30"

  tags = {
    Name = "inner-bastion-2"
  }
}

# Route53 records
resource "aws_route53_record" "inner_bastion_1" {
  zone_id = var.private_zone_id
  name    = "innerbastion01"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.inner_bastion_1.private_ip]
}

resource "aws_route53_record" "inner_bastion_2" {
  zone_id = var.private_zone_id
  name    = "innerbastion02"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.inner_bastion_2.private_ip]
}

resource "aws_route53_record" "bastion_failover_primary" {
  zone_id = var.public_zone_id
  name    = "bastion"
  type    = "A"
  ttl     = "300"

  set_identifier = "primary"
  records        = [aws_eip.inner_bastion_1.public_ip]

  health_check_id = aws_route53_health_check.inner_bastion_1.id

  failover_routing_policy {
    type = "PRIMARY"
  }
}

resource "aws_route53_record" "bastion_failover_secondary" {
  zone_id = var.public_zone_id
  name    = "bastion"
  type    = "A"
  ttl     = "300"

  set_identifier = "secondary"
  records        = [aws_eip.inner_bastion_2.public_ip]

  health_check_id = aws_route53_health_check.inner_bastion_2.id

  failover_routing_policy {
    type = "SECONDARY"
  }
}
