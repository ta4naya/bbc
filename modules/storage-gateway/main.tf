resource "aws_security_group" "sgw_sg" {
  name        = "sgw-sg"
  description = "Access to gateway"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 1026
    to_port     = 1031
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr, var.onprem_sgw_cidr]
  }

  ingress {
    from_port        = 2222
    to_port          = 2222
    protocol         = "tcp"
    cidr_blocks      = [var.subnet_private_a_cidr, var.subnet_private_b_cidr, var.onprem_sgw_cidr]
  }

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [var.subnet_private_a_cidr, var.subnet_private_b_cidr, var.onprem_sgw_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sgw-sg"
  }
}


resource "aws_vpc_endpoint" "storage_gateway" {
  vpc_id       = var.vpc_id
  service_name = var.gw_service_name
  vpc_endpoint_type = var.endpoint_type
  subnet_ids        = [var.subnet_private_a_id, var.subnet_private_b_id]
  security_group_ids = [aws_security_group.sgw_sg.id]
  private_dns_enabled = var.private_dns_enabled


  tags = {
    Name = "storage-gateway-vpc-endpoint"
  }
}

resource "aws_vpc_endpoint" "s3_private" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.eu-central-1.s3"
  vpc_endpoint_type   = var.endpoint_type
  subnet_ids          = [var.subnet_private_a_id, var.subnet_private_b_id]
  security_group_ids  = [
    aws_security_group.sgw_sg.id,
  ]
  private_dns_enabled = var.private_dns_enabled

  tags = {
    Name = "s3-private-endpoint"
  }
}

resource "aws_storagegateway_gateway" "storage_gateway" {
  gateway_name         = "bdpa-file-sgw"
  gateway_timezone     = "GMT+1:00"
  gateway_type         = "FILE_S3"
  # TODO: get IP from endpoint DNS
  gateway_vpc_endpoint = "10.60.57.191"
  activation_key       = var.sgw_activation_key
  smb_active_directory_settings {
    domain_name         = var.domain_name
    password            = var.password
    username            = var.username
    organizational_unit = var.organizational_unit
    domain_controllers  = var.domain_controllers
    timeout_in_seconds  = 300
  }

  tags = {
    Name = "onprem-storage-gateway"
  }
}

data "aws_storagegateway_local_disk" "sgw" {
  disk_node = "SCSI (0:1)"
  disk_path = "/dev/sdb"
  gateway_arn = aws_storagegateway_gateway.storage_gateway.arn
  depends_on = [aws_storagegateway_gateway.storage_gateway]
}

resource "aws_storagegateway_cache" "sgw_cache" {
  disk_id     = data.aws_storagegateway_local_disk.sgw.id
  gateway_arn = aws_storagegateway_gateway.storage_gateway.arn
  depends_on = [aws_storagegateway_gateway.storage_gateway]
  lifecycle {
    ignore_changes = [disk_id]
  }
}

resource "aws_s3_bucket" "smb_bucket" {
  bucket = "smb-fileshare-bucket-${var.aws_account_id}"
  lifecycle {
    prevent_destroy = true
  }
}

# # Allow HTTPS requests only
# https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html
resource "aws_s3_bucket_policy" "allow_https_only" {
  bucket = aws_s3_bucket.smb_bucket.id
  policy = data.aws_iam_policy_document.https_only.json
}

data "aws_iam_policy_document" "https_only" {
  statement {
    actions = ["s3:*"]
    effect  = "Deny"
    resources = [
      aws_s3_bucket.smb_bucket.arn,
      "${aws_s3_bucket.smb_bucket.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "sgw_bucket_access" {
  statement {
    actions = [
      "s3:GetAccelerateConfiguration",
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
      "s3:ListBucket",
      "s3:ListBucketVersions",
    ]
    effect  = "Allow"
    resources = [
      aws_s3_bucket.smb_bucket.arn,

    ]

  }
  statement {
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:GetObject",
      "s3:GetObjectAcl",
      "s3:GetObjectVersion",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]
    effect  = "Allow"
    resources = [
      "${aws_s3_bucket.smb_bucket.arn}/*",
    ]
 }
}


resource "aws_s3_bucket_acl" "default" {
  bucket = aws_s3_bucket.smb_bucket.id
  acl    = "private"
}

# Enable server-side encryption by default
resource "aws_s3_bucket_server_side_encryption_configuration" "default" {
  bucket = aws_s3_bucket.smb_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enable versioning by default
# resource "aws_s3_bucket_versioning" "enabled" {
#   bucket = aws_s3_bucket.smb_bucket.id
#   versioning_configuration {
#     status = "Enabled"
#   }
# }

# Block all public access to s3 buckets
resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.smb_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket.smb_bucket]
}

resource "aws_iam_role" "sgw_s3_access_role" {
  name               = "sgw-bucket-access-role"
  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "storagegateway.amazonaws.com"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": "${aws_storagegateway_gateway.storage_gateway.id}",
                    "aws:SourceAccount": "${var.aws_account_id}"
                }
            }
        }
    ]
  }
  EOF
}

resource "aws_iam_policy" "sgw_s3_access_policy" {
  name        = "sgw_s3_access_policy"
  policy = data.aws_iam_policy_document.sgw_bucket_access.json
}

resource "aws_iam_role_policy_attachment" "sgw_s3_access_policy_attachment" {
  role       = aws_iam_role.sgw_s3_access_role.name
  policy_arn = aws_iam_policy.sgw_s3_access_policy.arn
}

resource "aws_storagegateway_smb_file_share" "bdpa" {
  authentication = "ActiveDirectory"
  gateway_arn  = aws_storagegateway_gateway.storage_gateway.arn
  role_arn     = aws_iam_role.sgw_s3_access_role.arn
  location_arn = aws_s3_bucket.smb_bucket.arn
  bucket_region = "eu-central-1"
  vpc_endpoint_dns_name = trimprefix("${aws_vpc_endpoint.s3_private.dns_entry.0.dns_name}", "*.")
  depends_on = [aws_s3_bucket.smb_bucket, aws_iam_role.sgw_s3_access_role]
}
