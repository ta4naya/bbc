# Env vars
variable "env_label" {
  type        = string
  description = "Label to identify the environment (dev/test/prod)"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "eu-central-1"
}

variable "env_owner" {
  type        = string
  description = "Platform owner"
}

# VPC vars
variable "cidr_vpc" {
  type        = string
  description = "VPC CIDR block"
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

variable "cidr_bek_network" {
  type        = string
  description = "BEK network CIDR block"
  default     = "10.108.0.0/16"
}

# S3 vars
variable "bucket_prefix_logs" {
  type        = string
  description = "Prefix of S3 bucket storing service logs (e.g. S3, VPC, LB)"
}

variable "bucket_prefix_bastion_files" {
  type        = string
  description = "Prefix of S3 bucket storing the bastion files"
}

variable "bucket_prefix_private_files" {
  type        = string
  description = "Prefix of S3 bucket storing the private files"
}

# Bastion vars (EC2)
variable "inner_bastion_ec2_user" {
  type        = string
  description = "Default EC2 user on inner bastion"
}

variable "inner_bastion_sshd_port" {
  type        = string
  description = "SSH daemon port on inner bastion"
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

# Private instance vars (EC2)
variable "private_ec2_user" {
  type        = string
  description = "Default EC2 user on private hosts"
  default     = "centos"
}

variable "private_sshd_port" {
  type        = string
  description = "SSH daemon port on private hosts"
  default     = "22"
}

variable "jumpbox_ip_addr_list" {
  type        = list(string)
  description = "List of IP addresses from accepted jumpboxes"
}

# Route53 vars
variable "public_hosted_zone" {
  type        = string
  description = "Name of the public Route53 hosted zone"
}

variable "private_hosted_zone" {
  type        = string
  description = "Name of the private Route53 hosted zone"
}

# LB vars
variable "lb_type" {
  type        = string
  description = "Type of the load balancer"
  default     = "application"
}

# Elasticsearch vars
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
  default     = 2
}

variable "es_master_instance_type" {
  type        = string
  description = "Instance type of dedicated master nodes in the cluster"
}

variable "es_master_instance_count" {
  type        = number
  description = "Number of dedicated master nodes in the cluster"
  default     = 3
}

variable "es_ebs_volume_size" {
  type        = number
  description = "The size of EBS volumes attached to data nodes (in GiB)"
  default     = 100
}

variable "es_kibana_cognito_user_pool" {
  type        = string
  description = "Cognito user pool for Kibana"
  default     = "kibana_access"
}

variable "es_kibana_cognito_identity_pool" {
  type        = string
  description = "Cognito identity pool for Kibana"
  default     = "kibana_identities"
}

variable "es_snapshot_start_hour" {
  type        = number
  description = "Hour during which the service takes an automated daily snapshot of the indices in the domain"
  default     = 23
}

variable "logstash_instance_type" {
  type        = string
  description = "Instance type of logstash nodes"
}

# EKS vars
variable "surf_proxy_subnet_list" {
  type        = list(string)
  description = "List of subnets of the Bayer surf proxy infrastructure"
  default     = ["212.64.228.0/24"]
}


# Storage GW vars
variable "gw_service_name" {
  type        = string
  description = "The name of Endpoint service"
  default     = "com.amazonaws.eu-central-1.storagegateway"
}

variable "endpoint_type" {
  type        = string
  description = "The name of Endpoint type"
  default     = "Interface"
}

# variable "dns_record_ip_type" {
#   type        = string
#   description = "DNS record ip type"
#   default     = "ipv4"
# }

variable "private_dns_enabled" {
  type        = bool
  description = "Flag to indicate if private dns should be disabled "
  default     = false
}

variable "onprem_sgw_cidr" {
  type        = string
  description = "On premise storage gateway cidr"
  default     = "10.108.148.52/32"
}
