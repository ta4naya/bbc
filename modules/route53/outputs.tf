output "public_zone_id" {
  value = aws_route53_zone.bdpa_public.id
}

output "private_zone_id" {
  value = aws_route53_zone.bdpa_private.id
}
