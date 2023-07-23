output "vpc_enpoint_id" {
  value = module.file_gateway.vpc_enpoint_id
}

output "vpc_enpoint_dns" {
  value = module.file_gateway.vpc_enpoint_dns[0].dns_name
}

output "vpc_s3_enpoint_id" {
  value = module.file_gateway.vpc_s3_enpoint_id
}

output "vpc_s3_enpoint_dns" {
  value = trimprefix("${module.file_gateway.vpc_s3_enpoint_dns.0.dns_name}", "*.")
}
