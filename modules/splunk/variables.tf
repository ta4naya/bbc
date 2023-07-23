variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "bucket_private_files" {
  type        = string
  description = "ARN of S3 bucket storing the private files"
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "centos_ami_id" {
  type        = string
  description = "AMI id of CentOS 7 images"
}

variable "subnet_public_a_cidr" {
  type        = string
  description = "CIDR block of public subnet 1"
}

variable "subnet_public_b_cidr" {
  type        = string
  description = "CIDR block of public subnet 1"
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

variable "common_ssh_key_id" {
  type        = string
  description = "ID of ssh key to use"
}

variable "security_group_private_id" {
  type        = string
  description = "ID of private security group"
}

variable "private_ec2_user" {
  type        = string
  description = "Default EC2 user on private hosts"
}

variable "private_zone_id" {
  type        = string
  description = "ID of the private Route53 zone to create DNS records in"
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

variable "profile_private_name" {
  type        = string
  description = "Name of the IAM instance profile for private hosts"
}
