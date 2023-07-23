variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
}

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

variable "inner_bastion_files" {
  type        = string
  description = "Archive with files to install on the inner bastion"
}

variable "inner_bastion_bucket_path" {
  type        = string
  description = "S3 bucket path to install files for the inner bastion"
}
