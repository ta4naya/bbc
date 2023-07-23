variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
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

variable "security_group_inner_bastion_id" {
  type        = string
  description = "ID of inner bastion security group"
}
