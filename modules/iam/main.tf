resource "aws_iam_role" "bastion" {
  name = "bastion"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow"
      },
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "AWS": "arn:aws:iam::${var.aws_account_id}:role/cloudops"
        },
        "Effect": "Allow"
      }
    ]
  }
  EOF
}

resource "aws_iam_role" "private" {
  name = "private"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow"
      },
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "AWS": "arn:aws:iam::${var.aws_account_id}:role/cloudops"
        },
        "Effect": "Allow"
      }
    ]
  }
  EOF
}

resource "aws_iam_role_policy" "bastion" {
  name = "bastion"
  role = aws_iam_role.bastion.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:ListBucket"
        ],
        "Effect": "Allow",
        "Resource": "${var.bucket_bastion_files}"
      },
      {
        "Action": [
          "s3:ReadObject",
          "s3:GetObject"
        ],
        "Effect": "Allow",
        "Resource": "${var.bucket_bastion_files}/*"
      }
    ]
  }
  EOF
}

resource "aws_iam_role_policy" "private" {
  name = "private"
  role = aws_iam_role.private.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:ListBucket"
        ],
        "Effect": "Allow",
        "Resource": "${var.bucket_private_files}"
      },
      {
        "Action": [
          "s3:ReadObject",
          "s3:GetObject"
        ],
        "Effect": "Allow",
        "Resource": "${var.bucket_private_files}/*"
      }
    ]
  }
  EOF
}

resource "aws_iam_instance_profile" "bastion" {
  name = "bastion"
  role = aws_iam_role.bastion.id
}

resource "aws_iam_instance_profile" "private" {
  name = "private"
  role = aws_iam_role.private.id
}
