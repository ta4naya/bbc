output "instance_profile_bastion_name" {
  value = aws_iam_instance_profile.bastion.name
}

output "instance_profile_private_name" {
  value = aws_iam_instance_profile.private.name
}
