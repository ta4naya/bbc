output "vpc_id" {
  value = aws_vpc.main.id
}

output "subnet_public_a_id" {
  value = aws_subnet.public_a.id
}

output "subnet_public_b_id" {
  value = aws_subnet.public_b.id
}

output "subnet_public_a_cidr" {
  value = aws_subnet.public_a.cidr_block
}

output "subnet_public_b_cidr" {
  value = aws_subnet.public_b.cidr_block
}

output "subnet_private_a_id" {
  value = aws_subnet.private_a.id
}

output "subnet_private_b_id" {
  value = aws_subnet.private_b.id
}

output "subnet_private_a_cidr" {
  value = aws_subnet.private_a.cidr_block
}

output "subnet_private_b_cidr" {
  value = aws_subnet.private_b.cidr_block
}
