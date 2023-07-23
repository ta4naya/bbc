variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "bucket_bastion_files" {
  type        = string
  description = "ARN of S3 bucket storing the bastion files"
}

variable "bucket_private_files" {
  type        = string
  description = "ARN of S3 bucket storing the private files"
}
