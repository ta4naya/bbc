# Configure remote backend and required providers
terraform {
  backend "s3" {
    bucket         = "terraform-states-762052912533-eu-central-1"
    key            = "dev/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "terraform-locks-762052912533-eu-central-1"
  }
  required_providers {
    aws      = "~> 4.0"
    template = "~> 2.2"
    vault    = "~> 3.0"
  }
}

# Configure the AWS provider
provider "aws" {
  region = var.aws_region
}

# Configure Vault provider
provider "vault" {
  skip_child_token = true
}

# Configure service quotas
# resource "aws_servicequotas_service_quota" "eip" {
#   quota_code   = "L-F678F1CE"
#   service_code = "vpc"
#   value        = 10
# }

# Query data from effective AWS account
data "aws_caller_identity" "current" {}


# Locals
locals {
  aws_account_id           = data.aws_caller_identity.current.account_id
  scheduler_ec2tag_normal  = jsonencode({ "Type" = "Normal", "Timezone" = "Europe/Berlin", "Days" = "MON,TUE,WED,THU,FRI", "StartTime" = "08:00", "StopTime" = "18:00" })
  scheduler_ec2tag_24hours = jsonencode({ "Type" = "24hours", "Timezone" = "Europe/Berlin", "IsAllDays" = "true" })
  scheduler_rdstag_normal  = "+=Type=:=Normal=.=Timezone=:=Europe/Berlin=.=Days=:=MON.TUE.WED.THU.FRI=.=StartTime=:=0800=.=StopTime=:=1800=-"
  scheduler_rdstag_24hours = "+=Type=:=24hours=.=Timezone=:=Europe/Berlin=.=IsAllDays=:=true=-"
  public_subdomain_map     = {}
  private_subdomain_map    = {}
}

# Secrets
data "vault_kv_secret_v2" "storage_gateway" {
  mount = "kv"
  name  = "bdpa/aws/accounts/${local.aws_account_id}/storage-gateway"
}

# Define S3 module
module "s3" {
  source                      = "./modules/s3"
  bucket_prefix_logs          = var.bucket_prefix_logs
  bucket_prefix_bastion_files = var.bucket_prefix_bastion_files
  bucket_prefix_private_files = var.bucket_prefix_private_files
  aws_account_id              = local.aws_account_id
  aws_region                  = var.aws_region
  inner_bastion_bucket_path   = var.inner_bastion_bucket_path
  inner_bastion_files         = var.inner_bastion_files
}

# Define VPC module
module "vpc" {
  source                = "./modules/vpc"
  cidr_vpc              = var.cidr_vpc
  bucket_logs_arn       = module.s3.bucket_logs_arn
  cidr_subnet_public_a  = var.cidr_subnet_public_a
  cidr_subnet_public_b  = var.cidr_subnet_public_b
  cidr_subnet_private_a = var.cidr_subnet_private_a
  cidr_subnet_private_b = var.cidr_subnet_private_b
  bayer_connect_managed = var.bayer_connect_managed
}

# Define Route53 module
module "route53" {
  source                = "./modules/route53"
  env_label             = var.env_label
  public_hosted_zone    = var.public_hosted_zone
  vpc_id                = module.vpc.vpc_id
  private_hosted_zone   = var.private_hosted_zone
  public_subdomain_map  = local.public_subdomain_map
  private_subdomain_map = local.private_subdomain_map
}

# Define IAM module
module "iam" {
  source               = "./modules/iam"
  aws_account_id       = local.aws_account_id
  bucket_bastion_files = module.s3.bucket_bastion_files_arn
  bucket_private_files = module.s3.bucket_private_files_arn
}

# Define LB module
module "lb" {
  source             = "./modules/lb"
  vpc_id             = module.vpc.vpc_id
  lb_type            = var.lb_type
  subnet_public_a_id = module.vpc.subnet_public_a_id
  subnet_public_b_id = module.vpc.subnet_public_b_id
  bucket_logs        = "log-central-elb-640315046644-${var.aws_region}"
  prefix_logs        = "alb"
  public_hosted_zone = var.public_hosted_zone
}

# Define EC2 module
module "ec2" {
  source                     = "./modules/ec2"
  inner_bastion_ec2_user     = var.inner_bastion_ec2_user
  inner_bastion_sshd_svcname = var.inner_bastion_sshd_svcname
  inner_bastion_files        = var.inner_bastion_files
  inner_bastion_bucket_path  = var.inner_bastion_bucket_path
  bucket_bastion_files       = "${var.bucket_prefix_bastion_files}-${local.aws_account_id}-${var.aws_region}"
  inner_bastion_object_id    = module.s3.inner_bastion_object_id
  vpc_id                     = module.vpc.vpc_id
  jumpbox_ip_addr_list       = var.jumpbox_ip_addr_list
  inner_bastion_sshd_port    = var.inner_bastion_sshd_port
  private_sshd_port          = var.private_sshd_port
  subnet_public_a_id         = module.vpc.subnet_public_a_id
  subnet_public_b_id         = module.vpc.subnet_public_b_id
  profile_bastion_name       = module.iam.instance_profile_bastion_name
  scheduler_bastion_tag      = local.scheduler_ec2tag_24hours
  private_zone_id            = module.route53.private_zone_id
  public_zone_id             = module.route53.public_zone_id
}

# Define RDS module
module "rds" {
  source                          = "./modules/rds"
  vpc_id                          = module.vpc.vpc_id
  subnet_private_a_id             = module.vpc.subnet_private_a_id
  subnet_private_b_id             = module.vpc.subnet_private_b_id
  subnet_private_a_cidr           = module.vpc.subnet_private_a_cidr
  subnet_private_b_cidr           = module.vpc.subnet_private_b_cidr
  security_group_inner_bastion_id = module.ec2.security_group_inner_bastion_id
}

# Define DataHub endpoint module for AWS EU
# module "datahub_endpoint_euc1" {
#   source                        = "./modules/datahub-endpoint"
#   vpc_id                        = module.vpc.vpc_id
#   datahub_endpoint_service_name = "com.amazonaws.vpce.eu-central-1.vpce-svc-041c96d189d6d86dc"
#   subnet_private_a_id           = module.vpc.subnet_private_a_id
#   subnet_private_b_id           = module.vpc.subnet_private_b_id
#   subnet_private_a_cidr         = module.vpc.subnet_private_a_cidr
#   subnet_private_b_cidr         = module.vpc.subnet_private_b_cidr
#   datahub_hosted_zone_name      = "awseuc1.tst.edh.cnb"
#   datahub_region_name           = "euc1"
# }

# Define Icinga module
module "icinga" {
  source                      = "./modules/icinga"
  aws_account_id              = local.aws_account_id
  env_label                   = var.env_label
  private_ec2_user            = "rocky"
  vpc_id                      = module.vpc.vpc_id
  security_group_lb_id        = module.lb.security_group_lb_id
  subnet_private_a_cidr       = module.vpc.subnet_private_a_cidr
  subnet_private_b_cidr       = module.vpc.subnet_private_b_cidr
  bayer_connect_managed       = var.bayer_connect_managed
  cidr_bek_network            = var.cidr_bek_network
  rockylinux8_ami_id          = module.ec2.rockylinux8_ami_id
  common_ssh_key_id           = module.ec2.common_ssh_key_id
  security_group_private_id   = module.ec2.security_group_private_id
  subnet_private_a_id         = module.vpc.subnet_private_a_id
  subnet_private_b_id         = module.vpc.subnet_private_b_id
  private_zone_id             = module.route53.private_zone_id
  public_zone_id              = module.route53.public_zone_id
  public_hosted_zone          = var.public_hosted_zone
  ssl_listener_arn            = module.lb.ssl_listener_arn
  lb_dns_name                 = module.lb.lb_dns_name
  lb_zone_id                  = module.lb.lb_zone_id
  db_subnet_group_name        = module.rds.db_subnet_group_name
  security_group_rds_mysql_id = module.rds.security_group_rds_mysql_id
}

# Define Elasticsearch module
module "elasticsearch" {
  source                          = "./modules/elasticsearch"
  aws_region                      = var.aws_region
  aws_account_id                  = local.aws_account_id
  env_label                       = var.env_label
  public_hosted_zone              = var.public_hosted_zone
  eip_inner_bastion_1_public_ip   = module.ec2.eip_inner_bastion_1_public_ip
  eip_inner_bastion_2_public_ip   = module.ec2.eip_inner_bastion_2_public_ip
  private_ec2_user                = var.private_ec2_user
  vpc_id                          = module.vpc.vpc_id
  subnet_private_a_cidr           = module.vpc.subnet_private_a_cidr
  subnet_private_b_cidr           = module.vpc.subnet_private_b_cidr
  security_group_inner_bastion_id = module.ec2.security_group_inner_bastion_id
  security_group_lb_id            = module.lb.security_group_lb_id
  subnet_public_a_cidr            = module.vpc.subnet_public_a_cidr
  subnet_public_b_cidr            = module.vpc.subnet_public_b_cidr
  env_owner                       = var.env_owner
  oidc_client_id                  = var.oidc_client_id
  oidc_issuer                     = var.oidc_issuer
  es_version                      = var.es_version
  es_data_instance_type           = var.es_data_instance_type
  es_data_instance_count          = var.es_data_instance_count
  es_master_instance_type         = var.es_master_instance_type
  es_master_instance_count        = var.es_master_instance_count
  es_ebs_volume_size              = var.es_ebs_volume_size
  subnet_private_a_id             = module.vpc.subnet_private_a_id
  subnet_private_b_id             = module.vpc.subnet_private_b_id
  es_kibana_cognito_user_pool     = var.es_kibana_cognito_user_pool
  es_kibana_cognito_identity_pool = var.es_kibana_cognito_identity_pool
  es_snapshot_start_hour          = var.es_snapshot_start_hour
  logstash_instance_type          = var.logstash_instance_type
  centos_ami_id                   = module.ec2.centos_ami_id
  common_ssh_key_id               = module.ec2.common_ssh_key_id
  security_group_private_id       = module.ec2.security_group_private_id
  scheduler_logstash_tag          = local.scheduler_ec2tag_24hours
  private_zone_id                 = module.route53.private_zone_id
  public_zone_id                  = module.route53.public_zone_id
  ssl_listener_arn                = module.lb.ssl_listener_arn
  lb_dns_name                     = module.lb.lb_dns_name
  lb_zone_id                      = module.lb.lb_zone_id
}


# Define Storage Gateway module
module "file_gateway" {
  source          = "./modules/storage-gateway"
  vpc_id          = module.vpc.vpc_id
  gw_service_name = var.gw_service_name
  endpoint_type   = var.endpoint_type
  # dns_record_ip_type = var.dns_record_ip_type
  private_dns_enabled   = var.private_dns_enabled
  subnet_private_a_id   = module.vpc.subnet_private_a_id
  subnet_private_b_id   = module.vpc.subnet_private_b_id
  subnet_private_a_cidr = module.vpc.subnet_private_a_cidr
  subnet_private_b_cidr = module.vpc.subnet_private_b_cidr
  onprem_sgw_cidr       = var.onprem_sgw_cidr
  aws_account_id        = local.aws_account_id
  sgw_activation_key    = data.vault_kv_secret_v2.storage_gateway.data["activation_key"]
  domain_name           = "plt-bek.bhc.cnb"
  domain_controllers    = ["a018vmdc0101.plt-bek.bhc.cnb", "a018vmdc0104.plt-bek.bhc.cnb"]
  organizational_unit   = "OU=Linux,OU=Server,OU=Computer,OU=IT,DC=plt-bek,DC=bhc,DC=cnb"
  password              = data.vault_kv_secret_v2.storage_gateway.data["domainjoin_password"]
  username              = data.vault_kv_secret_v2.storage_gateway.data["domainjoin_username"]
}
