variable "inner_bastion_ec2_user" {
  type        = string
  description = "Default EC2 user on inner bastion"
}

variable "inner_bastion_sshd_svcname" {
  type        = string
  description = "SSH daemon service name on inner bastion"
}

variable "inner_bastion_files" {
  type        = string
  description = "Archive with files to install on the inner bastion"
}

variable "inner_bastion_bucket_path" {
  type        = string
  description = "S3 bucket path to install files for the inner bastion"
}

variable "bucket_bastion_files" {
  type        = string
  description = "Name of the bucket to use for bastion files"
}

variable "inner_bastion_object_id" {
  type        = string
  description = "ID of the script for initial configuration of EC2 instances - inner bastion"
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
}

variable "jumpbox_ip_addr_list" {
  type        = list(string)
  description = "List of IP addresses from accepted jumpboxes"
}

variable "inner_bastion_sshd_port" {
  type        = string
  description = "SSH daemon port on inner bastion"
}

variable "private_sshd_port" {
  type        = string
  description = "SSH daemon port on private hosts"
}

variable "subnet_public_a_id" {
  type        = string
  description = "ID of bastion subnet 1"
}

variable "subnet_public_b_id" {
  type        = string
  description = "ID of bastion subnet 2"
}

variable "profile_bastion_name" {
  type        = string
  description = "Name of the IAM instance profile for bastion hosts"
}

variable "scheduler_bastion_tag" {
  type        = string
  description = "ScheduleV2 tag for bastion hosts"
}

variable "private_zone_id" {
  type        = string
  description = "ID of the private Route53 zone to create DNS records in"
}

variable "public_zone_id" {
  type        = string
  description = "ID of the public Route53 zone to create DNS records in"
}
