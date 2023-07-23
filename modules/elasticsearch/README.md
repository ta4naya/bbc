# elasticsearch

Manage AWS Elasticsearch domain.

## Requirements

The following resources need to be configured before applying this module:

- Azure AD registered app to use with [AWS ES Cognito auth](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html)
- Following secrets stored in Vault:
  - OIDC client secret for Cognito IdP (secret path: `bdpa/aws/accounts/<aws_account_id>/elasticsearch`, secret key: `cognito_oidc_client_secret`)
  - Username for the IAM master user with Cognito authentication for Kibana (secret path: `bdpa/aws/accounts/<aws_account_id>/elasticsearch`, secret key: `cognito_master_user_username`)
  - Password for the IAM master user with Cognito authentication for Kibana (secret path: `bdpa/aws/accounts/<aws_account_id>/elasticsearch`, secret key: `cognito_master_user_password`)
- Public domain (e.g. Route53 hosted zone) for the custom endpoint
- Imported ACM certificate for the custom endpoint (CN: `es.<public_hosted_zone>`)
- Template for the user data script to bootstrap Elastic EC2 instances (logstash, ES management)

  Place template into TF root `templates/private.tpl`, example:

  ```bash
  #!/bin/bash

  # add ssh keys to the `${ec2_user}` user

  echo "ssh-rsa AAAAB3NzaC1yc2EAAAA... firstname.lastname@bayer.com" > /home/${ec2_user}/.ssh/authorized_keys
  chown ${ec2_user}: /home/${ec2_user}/.ssh/authorized_keys
  chmod 0600 /home/${ec2_user}/.ssh/authorized_keys
  ```

## Providers

| Name | Version |
|------|---------|
| aws | n/a |
| template | n/a |

## Inputs

| Variable | Description |
| ------ | ----------- |
| aws_region | Tbd. |
| aws_account_id | Tbd. |
| env_label | Tbd. |
| public_hosted_zone | Tbd. |
| eip_inner_bastion_1_public_ip | Tbd. |
| eip_inner_bastion_2_public_ip | Tbd. |
| private_ec2_user | Tbd. |
| vpc_id | Tbd. |
| subnet_private_a_cidr | Tbd. |
| subnet_private_b_cidr | Tbd. |
| security_group_inner_bastion_id | Tbd. |
| security_group_lb_id | Tbd. |
| subnet_public_a_cidr | Tbd. |
| subnet_public_b_cidr | Tbd. |
| env_owner | Tbd. |
| oidc_client_id | Tbd. |
| oidc_issuer | Tbd. |
| es_version | Tbd. |
| es_data_instance_type | Tbd. |
| es_data_instance_count | Tbd. |
| es_master_instance_type | Tbd. |
| es_master_instance_count | Tbd. |
| es_ebs_volume_size | Tbd. |
| subnet_private_a_id | Tbd. |
| subnet_private_b_id | Tbd. |
| es_kibana_cognito_user_pool | Tbd. |
| es_kibana_cognito_identity_pool | Tbd. |
| es_snapshot_start_hour | Tbd. |
| centos_ami_id | Tbd. |
| common_ssh_key_id | Tbd. |
| security_group_private_id | Tbd. |
| scheduler_logstash_tag | Tbd. |
| private_zone_id | Tbd. |
| public_zone_id | Tbd. |
| ssl_listener_arn | Tbd. |
| lb_dns_name | Tbd. |
| lb_zone_id | Tbd. |

## Outputs

| Value | Description |
| ------ | ----------- |
| es_endpoint | Domain-specific endpoint used to submit index, search, and data upload requests. |
| es_kibana_endpoint | Domain-specific endpoint for kibana without https scheme. |
