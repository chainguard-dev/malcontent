
rule iptables_upload_http : critical {
	meta:
		description = "Uploads, uses iptables and HTTP"
	strings:
		$ref1 = "upload"
		$ref2 = "HTTP"
		$ref3 = "iptables"
	condition:
		all of them
}