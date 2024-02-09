
rule gethostbyname {
	meta:
		description = "Uses libc functions to resolve network hosts"
		pledge = "inet"
	strings:
		$gethostbyname2 = "gethostbyname2" fullword
		$gethostbyname = "gethostbyname" fullword
	condition:
		any of them
}
rule refs {
	meta:
		description = "Resolves network host names"
	strings:
		$cannot_resolve = "cannot resolve"
	condition:
		any of them
}

rule go {
	meta:
		description = "Uses Go to resolve network hosts"
	strings:
		$net_lookup = "net.hostLookup"
	condition:
		any of them
}