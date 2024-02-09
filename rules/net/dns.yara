rule dns_refs {
	meta:
		description = "Uses DNS (Domain Name Service)"
	strings:
		$dnsmessage = "dnsmessage"
	condition:
		any of them
}
