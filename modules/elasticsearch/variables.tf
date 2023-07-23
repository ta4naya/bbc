variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "env_label" {
  type        = string
  description = "Label to identify the environment (dev/test/prod)"
}

variable "public_hosted_zone" {
  type        = string
  description = "Name of the public Route53 hosted zone"
}

variable "eip_inner_bastion_1_public_ip" {
  type        = string
  description = "Public IP (EIP) of the inner bastion 1"
}

variable "eip_inner_bastion_2_public_ip" {
  type        = string
  description = "Public IP (EIP) of the inner bastion 2"
}

variable "private_ec2_user" {
  type        = string
  description = "Default EC2 user on private hosts"
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC to create the objects in"
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

variable "security_group_lb_id" {
  type        = string
  description = "ID of load balancer security group"
}

variable "subnet_public_a_cidr" {
  type        = string
  description = "CIDR block of public subnet 1"
}

variable "subnet_public_b_cidr" {
  type        = string
  description = "CIDR block of public subnet 2"
}

variable "env_owner" {
  type        = string
  description = "Platform owner"
}

variable "oidc_client_id" {
  type        = string
  description = "Unique application ID for OIDC IdP"
}

variable "oidc_issuer" {
  type        = string
  description = "URL of OpenID Connect metadata document"
}

variable "es_version" {
  type        = string
  description = "Elasticsearch version"
}

variable "es_data_instance_type" {
  type        = string
  description = "Instance type of data nodes in the cluster"
}

variable "es_data_instance_count" {
  type        = number
  description = "Number of data nodes in the cluster"
}

variable "es_master_instance_type" {
  type        = string
  description = "Instance type of dedicated master nodes in the cluster"
}

variable "es_master_instance_count" {
  type        = number
  description = "Number of dedicated master nodes in the cluster"
}

variable "es_ebs_volume_size" {
  type        = number
  description = "The size of EBS volumes attached to data nodes (in GiB)"
}

variable "subnet_private_a_id" {
  type        = string
  description = "ID of private subnet 1"
}

variable "subnet_private_b_id" {
  type        = string
  description = "ID of private subnet 2"
}

variable "es_kibana_cognito_user_pool" {
  type        = string
  description = "Cognito user pool for Kibana"
}

variable "es_kibana_cognito_identity_pool" {
  type        = string
  description = "Cognito identity pool for Kibana"
}

variable "es_snapshot_start_hour" {
  type        = number
  description = "Hour during which the service takes an automated daily snapshot of the indices in the domain"
}

variable "logstash_instance_type" {
  type        = string
  description = "Instance type of logstash nodes"
}

variable "centos_ami_id" {
  type        = string
  description = "AMI id of CentOS 7 images"
}

variable "common_ssh_key_id" {
  type        = string
  description = "ID of ssh key to use"
}

variable "security_group_private_id" {
  type        = string
  description = "ID of private security group"
}

variable "scheduler_logstash_tag" {
  type        = string
  description = "ScheduleV2 tag for logstash hosts"
}

variable "private_zone_id" {
  type        = string
  description = "ID of the private Route53 zone to create DNS records in"
}

variable "public_zone_id" {
  type        = string
  description = "ID of the public Route53 zone to create DNS records in"
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
