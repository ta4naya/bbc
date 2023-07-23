data "aws_elb_service_account" "this" {}

resource "aws_s3_bucket" "logs" {
  bucket = "${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}"
  acl    = "log-delivery-write"

  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:*"
        ],
        "Effect": "Deny",
        "Resource": [
          "arn:aws:s3:::${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}",
          "arn:aws:s3:::${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}/*"
        ],
        "Principal": "*",
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      },
      {
        "Action": [
          "s3:PutObject"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:s3:::${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}/AWSLogs/*",
        "Principal": {
          "AWS": [
            "${data.aws_elb_service_account.this.arn}"
          ]
        }
      },
      {
        "Action": [
          "s3:PutObject"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:s3:::${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}/AWSLogs/*",
        "Principal": {
          "Service": "delivery.logs.amazonaws.com"
        },
        "Condition": {
          "StringEquals": {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      },
      {
        "Action": [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:s3:::${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}",
        "Principal": {
          "Service": "delivery.logs.amazonaws.com"
        }
      }
    ]
  }
  EOF
}

resource "aws_s3_bucket" "bastion_files" {
  bucket = "${var.bucket_prefix_bastion_files}-${var.aws_account_id}-${var.aws_region}"
  acl    = "private"

  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:*"
        ],
        "Effect": "Deny",
        "Resource": [
          "arn:aws:s3:::${var.bucket_prefix_bastion_files}-${var.aws_account_id}-${var.aws_region}",
          "arn:aws:s3:::${var.bucket_prefix_bastion_files}-${var.aws_account_id}-${var.aws_region}/*"
        ],
        "Principal": "*",
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  }
  EOF

  logging {
    target_bucket = "${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}"
    target_prefix = "AWSLogs/${var.aws_account_id}/simplestorageservice/${var.aws_region}/${var.bucket_prefix_bastion_files}/"
  }

  depends_on = [aws_s3_bucket.logs]
}

resource "aws_s3_bucket" "private_files" {
  bucket = "${var.bucket_prefix_private_files}-${var.aws_account_id}-${var.aws_region}"
  acl    = "private"

  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:*"
        ],
        "Effect": "Deny",
        "Resource": [
          "arn:aws:s3:::${var.bucket_prefix_private_files}-${var.aws_account_id}-${var.aws_region}",
          "arn:aws:s3:::${var.bucket_prefix_private_files}-${var.aws_account_id}-${var.aws_region}/*"
        ],
        "Principal": "*",
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  }
  EOF

  logging {
    target_bucket = "${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}"
    target_prefix = "AWSLogs/${var.aws_account_id}/simplestorageservice/${var.aws_region}/${var.bucket_prefix_private_files}/"
  }

  depends_on = [aws_s3_bucket.logs]
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = "${var.bucket_prefix_logs}-${var.aws_account_id}-${var.aws_region}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.logs]
}

resource "aws_s3_bucket_public_access_block" "bastion_files" {
  bucket = "${var.bucket_prefix_bastion_files}-${var.aws_account_id}-${var.aws_region}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.bastion_files]
}

resource "aws_s3_bucket_public_access_block" "private_files" {
  bucket = "${var.bucket_prefix_private_files}-${var.aws_account_id}-${var.aws_region}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.private_files]
}

resource "aws_s3_bucket_object" "inner_bastion_files" {
  bucket                 = aws_s3_bucket.bastion_files.id
  key                    = "${var.inner_bastion_bucket_path}/${var.inner_bastion_files}"
  source                 = "files/${var.inner_bastion_files}"
  server_side_encryption = "AES256"
  etag                   = filemd5("files/${var.inner_bastion_files}")
}
