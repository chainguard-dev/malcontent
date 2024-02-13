rule dns_refs {
	meta:
		description = "Uses DNS TXT (text) records"
	strings:
		$dns = "dns"
		$txt = "TXT"
	condition:
		all of them
}
