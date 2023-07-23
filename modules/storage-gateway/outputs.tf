output "vpc_enpoint_id" {
  value = aws_vpc_endpoint.storage_gateway.id
}

output "vpc_enpoint_dns" {
  value = aws_vpc_endpoint.storage_gateway.dns_entry
}

output "vpc_s3_enpoint_id" {
  value = aws_vpc_endpoint.s3_private.id
}

output "vpc_s3_enpoint_dns" {
  value = aws_vpc_endpoint.s3_private.dns_entry
}
