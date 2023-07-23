output "security_group_lb_id" {
  value = aws_security_group.lb.id
}

output "ssl_listener_arn" {
  value = aws_lb_listener.main_ssl.arn
}

output "lb_dns_name" {
  value = aws_lb.main.dns_name
}

output "lb_zone_id" {
  value = aws_lb.main.zone_id
}
