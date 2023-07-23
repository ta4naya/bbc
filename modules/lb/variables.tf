variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "lb_type" {
  type        = string
  description = "Type of the load balancer"
}

variable "subnet_public_a_id" {
  type        = string
  description = "ID of bastion subnet 1"
}

variable "subnet_public_b_id" {
  type        = string
  description = "ID of bastion subnet 2"
}

variable "bucket_logs" {
  type        = string
  description = "Name of S3 bucket storing the elastic load balancer access logs"
}

variable "prefix_logs" {
  type        = string
  description = "Prefix of S3 bucket storing the elastic load balancer access logs"
}

variable "public_hosted_zone" {
  type        = string
  description = "Name of the public Route53 hosted zone"
}
