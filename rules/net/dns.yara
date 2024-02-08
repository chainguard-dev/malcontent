rule dns_refs {
	strings:
		$dnsmessage = "dnsmessage"
	condition:
		any of them
}
