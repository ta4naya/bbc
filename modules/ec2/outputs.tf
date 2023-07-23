output "centos_ami_id" {
  value = element(concat(data.aws_ami_ids.centos.ids, tolist([""])), 0)
}

output "rockylinux8_ami_id" {
  value = element(concat(data.aws_ami_ids.rockylinux8.ids, tolist([""])), 0)
}

output "common_ssh_key_id" {
  value = aws_key_pair.shygd.id
}

output "security_group_private_id" {
  value = aws_security_group.private.id
}

output "security_group_inner_bastion_id" {
  value = aws_security_group.inner_bastion.id
}

output "eip_inner_bastion_1_public_ip" {
  value = aws_eip.inner_bastion_1.public_ip
}

output "eip_inner_bastion_2_public_ip" {
  value = aws_eip.inner_bastion_2.public_ip
}
