resource "aws_security_group" "lb" {
  name        = "lb"
  description = "Access to load balancer"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lb"
  }
}

resource "aws_lb" "main" {
  name               = "main"
  internal           = false
  load_balancer_type = var.lb_type
  security_groups    = [aws_security_group.lb.id]
  subnets            = [var.subnet_public_a_id, var.subnet_public_b_id]

  access_logs {
    bucket  = var.bucket_logs
    prefix  = var.prefix_logs
    enabled = true
  }

  tags = {
    Name = "main"
  }
}

resource "aws_acm_certificate" "cert" {
  domain_name       = replace(var.public_hosted_zone, "/[.]$/", "")
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_route53_zone" "bdpa" {
  name         = var.public_hosted_zone
  private_zone = false
}

resource "aws_route53_record" "cert_validation" {
  name    = tolist(aws_acm_certificate.cert.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.cert.domain_validation_options)[0].resource_record_type
  zone_id = data.aws_route53_zone.bdpa.zone_id
  records = [tolist(aws_acm_certificate.cert.domain_validation_options)[0].resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [aws_route53_record.cert_validation.fqdn]
}

resource "aws_lb_listener" "main_plain" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "main_ssl" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.cert.certificate_arn

  default_action {
    type             = "fixed-response"

    fixed_response {
      content_type = "text/html"
      message_body = "<center><h1>200 OK</h1></center>"
      status_code  = "200"
    }
  }
}

resource "aws_route53_record" "bdpa" {
  zone_id = data.aws_route53_zone.bdpa.id
  name    = data.aws_route53_zone.bdpa.name
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
