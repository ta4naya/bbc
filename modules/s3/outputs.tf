output "bucket_bastion_files_arn" {
  value = aws_s3_bucket.bastion_files.arn
}

output "bucket_private_files_arn" {
  value = aws_s3_bucket.private_files.arn
}

output "bucket_logs_arn" {
  value = aws_s3_bucket.logs.arn
}

output "inner_bastion_object_id" {
  value = "aws_s3_bucket_object.inner_bastion_files.id"
}
