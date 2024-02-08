rule aws_metadata {
	strings:
		$ref = "X-aws-ec2-metadata-token"
	condition:
		any of them
}



