#bbc

[![CI](https://github.com/bayer-int/bdpa-tf-bag-bdpa-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/bayer-int/bdpa-tf-bag-bdpa-dev/actions/workflows/ci.yml)

Terraform code for the bag-bdpa-dev SMART 2.0 AWS account.

## Usage

Follow these instructions to manually deploy basic dev infrastructure.

```shell
edh-aws-sso -u REPLACE_WITH_YOUR_BAYER_EMAIL_ADDRESS
terraform init
terraform validate
terraform fmt -check
terraform plan
terraform apply
```

## Elasticsearch service

After configuring the custom endpoint update the Cognito app client settings (Cognito > User Pools > kibana_access > App integration > App client settings). Enable the `AzureAD` IdP and in the **OAuth 2.0** section disable the `phone` scope.

Last but not least, update the **Cognito authentication provider** (Cognito > Federated Identities > kibana_identities > Edit identity pool > Authentication providers > Cognito). For **Authenticated role selection** select `Choose role from token` and set the **Role resolution** to `DENY`.

Important: With everything deployed, you should login at least once with the `master-user` and change its temporary password.
