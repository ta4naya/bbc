variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "datahub_endpoint_service_name" {
  type        = string
  description = "The name of Endpoint service for DataHub"
}

variable "subnet_private_a_id" {
  type        = string
  description = "ID of private subnet 1"
}

variable "subnet_private_b_id" {
  type        = string
  description = "ID of private subnet 2"
}

variable "subnet_private_a_cidr" {
  type        = string
  description = "CIDR block of private subnet 1"
}

variable "subnet_private_b_cidr" {
  type        = string
  description = "CIDR block of private subnet 2"
}

variable "datahub_hosted_zone_name" {
  type        = string
  description = "The name of the Route53 Hosted Zone for DataHub"
}

variable "datahub_region_name" {
  type        = string
  description = "The name of the AWS Region for DataHub"
}
