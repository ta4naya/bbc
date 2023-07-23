# VPC vars
variable "cidr_vpc" {
  type        = string
  description = "VPC CIDR block"
}

variable "bucket_logs_arn" {
  type        = string
  description = "ARN of S3 bucket storing the VPC flow logs"
}

variable "cidr_subnet_public_a" {
  type        = string
  description = "Public subnet CIDR block (euc1a)"
}

variable "cidr_subnet_public_b" {
  type        = string
  description = "Public subnet CIDR block (euc1b)"
}

variable "cidr_subnet_private_a" {
  type        = string
  description = "Private subnet CIDR block (euc1a)"
}

variable "cidr_subnet_private_b" {
  type        = string
  description = "Private subnet CIDR block (euc1b)"
}

variable "bayer_connect_managed" {
  type        = bool
  description = "Flag to indicate if VPC is connected to Bayer's corporate network"
}
