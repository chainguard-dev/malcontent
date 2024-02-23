
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