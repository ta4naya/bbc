output "db_subnet_group_name" {
  value = aws_db_subnet_group.default.name
}

output "security_group_rds_mysql_id" {
  value = aws_security_group.rds_mysql.id
}

output "security_group_rds_postgres_id" {
  value = aws_security_group.rds_postgres.id
}
