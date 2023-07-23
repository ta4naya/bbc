resource "aws_security_group" "datahub_endpoint" {
  name        = "datahub-endpoint-${var.datahub_region_name}"
  description = "Allow communication with the DataHub from VPC private subnets"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow traffic to the schema registry"
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description = "Allow traffic to a randomly chosen broker"
    from_port   = 9093
    to_port     = 9093
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description = "Allow traffic to a certain broker"
    from_port   = 19301
    to_port     = 19399
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
    Name = "datahub-endpoint-${var.datahub_region_name}"
  }
}

resource "aws_vpc_endpoint" "datahub_endpoint" {
  vpc_id            = var.vpc_id
  service_name      = var.datahub_endpoint_service_name
  vpc_endpoint_type = "Interface"

  security_group_ids = [aws_security_group.datahub_endpoint.id]

  subnet_ids          = [var.subnet_private_a_id, var.subnet_private_b_id]
  private_dns_enabled = false

  tags = {
    Name = "datahub-endpoint-${var.datahub_region_name}"
  }
}

# TODO: Check if this is still required
# resource "aws_security_group" "aws_endpoint" {
#   name        = "aws-endpoint"
#   description = "Allow communication with AWS service endpoints from VPC private subnets"
#   vpc_id      = var.vpc_id

#   ingress {
#     description = "Allow traffic to AWS service endpoints"
#     from_port   = 443
#     to_port     = 443
#     protocol    = "tcp"
#     cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

resource "aws_route53_zone" "datahub_hosted_zone" {
  name = var.datahub_hosted_zone_name

  vpc {
    vpc_id = var.vpc_id
  }
}

resource "aws_route53_record" "kafka" {
  zone_id = aws_route53_zone.datahub_hosted_zone.zone_id
  name    = "kafka.${var.datahub_hosted_zone_name}"
  type    = "A"

  alias {
    name                   = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.dns_name
    zone_id                = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "kfk" {
  zone_id = aws_route53_zone.datahub_hosted_zone.zone_id
  name    = "kfk.${var.datahub_hosted_zone_name}"
  type    = "A"

  alias {
    name                   = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.dns_name
    zone_id                = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "schema-registry" {
  zone_id = aws_route53_zone.datahub_hosted_zone.zone_id
  name    = "schema-registry.${var.datahub_hosted_zone_name}"
  type    = "A"

  alias {
    name                   = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.dns_name
    zone_id                = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "sr" {
  zone_id = aws_route53_zone.datahub_hosted_zone.zone_id
  name    = "sr.${var.datahub_hosted_zone_name}"
  type    = "A"

  alias {
    name                   = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.dns_name
    zone_id                = aws_vpc_endpoint.datahub_endpoint.dns_entry.0.hosted_zone_id
    evaluate_target_health = false
  }
}
