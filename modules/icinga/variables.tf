variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "env_label" {
  type        = string
  description = "Label to identify the environment (dev/test/prod)"
}

variable "private_ec2_user" {
  type        = string
  description = "Default EC2 user on private hosts"
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "security_group_lb_id" {
  type        = string
  description = "ID of load balancer security group"
}

variable "subnet_private_a_cidr" {
  type        = string
  description = "CIDR block of private subnet 1"
}

variable "subnet_private_b_cidr" {
  type        = string
  description = "CIDR block of private subnet 2"
}

variable "bayer_connect_managed" {
  type        = bool
  description = "Flag to indicate if VPC is connected to Bayer's corporate network"
}

variable "cidr_bek_network" {
  type        = string
  description = "BEK network CIDR block"
}

variable "rockylinux8_ami_id" {
  type        = string
  description = "AMI id of Rocky Linux 8 images"
}

variable "common_ssh_key_id" {
  type        = string
  description = "ID of ssh key to use"
}

variable "security_group_private_id" {
  type        = string
  description = "ID of private security group"
}

variable "subnet_private_a_id" {
  type        = string
  description = "ID of private subnet 1"
}

variable "subnet_private_b_id" {
  type        = string
  description = "ID of private subnet 2"
}

variable "private_zone_id" {
  type        = string
  description = "ID of the private Route53 zone to create DNS records in"
}

variable "public_zone_id" {
  type        = string
  description = "ID of the public Route53 zone to create DNS records in"
}

variable "public_hosted_zone" {
  type        = string
  description = "Name of the public Route53 hosted zone"
}

variable "ssl_listener_arn" {
  type        = string
  description = "ARN of the load balancer's SSL listener"
}

variable "lb_dns_name" {
  type        = string
  description = "DNS name of the load balancer"
}

variable "lb_zone_id" {
  type        = string
  description = "Zone ID of the load balancer"
}

variable "db_subnet_group_name" {
  type        = string
  description = "Name of DB subnet group"
}

variable "security_group_rds_mysql_id" {
  type        = string
  description = "ID of MySQL security group"
}
