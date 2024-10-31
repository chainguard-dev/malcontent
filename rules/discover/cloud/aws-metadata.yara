rule aws_metadata {
  meta:
    description = "References the AWS EC2 metadata token"

  strings:
    $ref = "X-aws-ec2-metadata-token"

  condition:
    any of them
}

