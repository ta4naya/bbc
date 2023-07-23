# Env vars
env_label = "dev"
env_owner = "bdpa"

# VPC vars
cidr_vpc              = "10.60.56.0/22"
cidr_subnet_public_a  = "10.60.56.0/25"
cidr_subnet_public_b  = "10.60.56.128/25"
cidr_subnet_private_a = "10.60.57.0/24"
cidr_subnet_private_b = "10.60.58.0/24"
bayer_connect_managed = true

# S3 vars
bucket_prefix_logs          = "logs"
bucket_prefix_bastion_files = "bastion-files"
bucket_prefix_private_files = "private-files"

# Bastion vars (EC2)
inner_bastion_ec2_user     = "centos"
inner_bastion_sshd_port    = "22"
inner_bastion_sshd_svcname = "sshd"
inner_bastion_files        = "inner-bastion.tgz"
inner_bastion_bucket_path  = "inner-bastion"
jumpbox_ip_addr_list       = ["52.22.113.235", "52.39.76.251", "18.193.100.228", "122.248.222.142"]

# Route53 vars
public_hosted_zone  = "bdpa-infra-np.bayer.com."
private_hosted_zone = "bdpa.local."

# Elasticsearch vars
oidc_client_id          = "6f3baa90-0188-4c2c-befd-1c0122a73ac8"
oidc_issuer             = "https://login.microsoftonline.com/fcb2b37b-5da0-466b-9b83-0014b67a7c78/v2.0"
es_version              = "OpenSearch_1.3"
es_data_instance_type   = "m5.large.elasticsearch"
es_master_instance_type = "t3.medium.elasticsearch"
es_ebs_volume_size      = 100
logstash_instance_type  = "c5.xlarge"
