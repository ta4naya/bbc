variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "gw_service_name" {
  type        = string
  description = "The name of Endpoint service"
}

variable "endpoint_type" {
  type        = string
  description = "The name of Endpoint type"
}

variable "subnet_private_a_id" {
  type        = string
  description = "ID of private subnet 1"
}

variable "subnet_private_b_id" {
  type        = string
  description = "ID of private subnet 2"
}

# variable "dns_record_ip_type" {
#   type        = string
#   description = "DNS record ip type"
# }

variable "private_dns_enabled" {
  type        = bool
  description = "Flag to indicate if private dns should be disabled "
}

variable "subnet_private_a_cidr" {
  type        = string
  description = "CIDR block of private subnet 1"
}

variable "subnet_private_b_cidr" {
  type        = string
  description = "CIDR block of private subnet 2"
}

variable "onprem_sgw_cidr" {
  type        = string
  description = "On premise storage gateway cidr"
}

variable "sgw_activation_key" {
  type        = string
  description = "storage gateway activation key"
}

variable "domain_name" {
  type        = string
  description = "SMB AD Domain name"
}

variable "organizational_unit" {
  type        = string
  description = "SMB AD OU"
}

variable "domain_controllers" {
  type        = list(string)
  description = "SMB AD DC"
}

variable "username" {
  type        = string
  description = "SMB AD Admin Username"
}

variable "password" {
  type        = string
  description = "SMB AD Password"
}
