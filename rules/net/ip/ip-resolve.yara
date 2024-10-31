
rule gethostbyaddr {
	meta:
		description = "resolves network hosts via IP address"
		ref = "https://linux.die.net/man/3/gethostbyaddr"
		pledge = "dns"
	strings:
		$gethostbyname2 = "gethostbyaddr" fullword
	condition:
		any of them
}