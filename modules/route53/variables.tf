variable "env_label" {
  type        = string
  description = "Label to identify the environment (dev/test/prod)"
}

variable "public_hosted_zone" {
  type        = string
  description = "Name of the public Route53 hosted zone"
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "private_hosted_zone" {
  type        = string
  description = "Name of the private Route53 hosted zone"
}

variable "public_subdomain_map" {
  type        = map(any)
  description = "Map of public Route53 subdomains"
}

variable "private_subdomain_map" {
  type        = map(any)
  description = "Map of private Route53 subdomains"
}
