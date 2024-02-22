
rule gethostbyaddr {
	meta:
		description = "resolves network hosts via IP address"
		pledge = "dns"
	strings:
		$gethostbyname2 = "gethostbyaddr" fullword
	condition:
		any of them
}