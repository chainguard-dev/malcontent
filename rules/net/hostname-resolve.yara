rule gethostbyname {
	meta:
		description = "resolves network hosts via name"
		pledge = "inet"
		ref = "https://linux.die.net/man/3/gethostbyname"
	strings:
		$gethostbyname2 = "gethostbyname" fullword
	condition:
		any of them
}


rule gethostbyname2 {
	meta:
		description = "resolves network hosts via name"
		pledge = "inet"
		ref = "https://linux.die.net/man/3/gethostbyname2"
	strings:
		$gethostbyname2 = "gethostbyname2" fullword
	condition:
		any of them
}

rule cannot_resolve {
	meta:
		description = "Resolves network host names"
	strings:
		$cannot_resolve = "cannot resolve"
	condition:
		any of them
}

rule net_hostlookup {
	meta:
		description = "Uses Go to resolve network hosts"
	strings:
		$net_lookup = "net.hostLookup"
		$hostip = "LookupHostIP"
	condition:
		any of them
}