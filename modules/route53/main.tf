resource "aws_route53_zone" "bdpa_public" {
  name = var.public_hosted_zone

  tags = {
    Environment = var.env_label
  }
}

resource "aws_route53_zone" "bdpa_private" {
  name = "${var.env_label}.${var.private_hosted_zone}"

  vpc {
    vpc_id = var.vpc_id
  }

  tags = {
    Environment = var.env_label
  }
}

resource "aws_route53_record" "bdpa_public_subdomain" {
  for_each = var.public_subdomain_map

  zone_id = aws_route53_zone.bdpa_public.zone_id
  name    = "${each.key}.${var.public_hosted_zone}"
  type    = "NS"
  ttl     = "172800"
  records = each.value.ns
}

resource "aws_route53_record" "bdpa_private_subdomain" {
  for_each = var.private_subdomain_map

  zone_id = aws_route53_zone.bdpa_private.zone_id
  name    = "${each.key}.${var.env_label}.${var.private_hosted_zone}"
  type    = "NS"
  ttl     = "172800"
  records = each.value.ns
}
