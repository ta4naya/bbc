resource "aws_db_subnet_group" "default" {
  name        = "main"
  description = "Default DB subnet group"
  subnet_ids  = [var.subnet_private_a_id, var.subnet_private_b_id]

  tags = {
    Name = "db-subnetgrp"
  }
}

resource "aws_security_group" "rds_mysql" {
  name        = "rds-mysql"
  description = "Access to MySQL RDS"
  vpc_id      = var.vpc_id

  ingress {
    description = "Access from private subnets"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description     = "Access from inner bastion"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [var.security_group_inner_bastion_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "rds-mysql"
  }
}

resource "aws_security_group" "rds_postgres" {
  name        = "rds-postgres"
  description = "Access to PostgreSQL RDS"
  vpc_id      = var.vpc_id

  ingress {
    description = "Access from private subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.subnet_private_a_cidr, var.subnet_private_b_cidr]
  }

  ingress {
    description     = "Access from inner bastion"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.security_group_inner_bastion_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "rds-postgres"
  }
}
