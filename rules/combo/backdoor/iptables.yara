
rule iptables_upload_http : suspicious {
	meta:
		description = "Uploads, uses iptables and HTTP"
	strings:
		$ref1 = "upload"
		$ref2 = "HTTP"
		$ref3 = "iptables"
	condition:
		all of them
}


rule iptables_ssh : notable {
	meta:
		description = "Supports iptables and ssh"
	strings:
		$socks5 = "iptables" fullword
		$ssh = "ssh" fullword
	condition:
		all of them
}


rule iptables_gdns_http : suspicious {
	meta:
		description = "Uses iptables, Google Public DNS, and HTTP"
	strings:
		$ref1 = "iptables"
		$ref2 = "8.8.8.8"
		$ref3 = "HTTP"
	condition:
		all of them
}