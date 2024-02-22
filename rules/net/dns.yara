rule go_dns_refs {
	meta:
		description = "Uses DNS (Domain Name Service)"
	strings:
		$dnsmessage = "dnsmessage"
		$edns = "SetEDNS0"
		$cname = "CNAMEResource"
	condition:
		any of them
}
