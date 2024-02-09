
rule fcntl {
	meta:
		pledge = "wpath"
		description = "manipulate file descriptor"
		// sometimes CAP_LEASE
	strings:
		$ref = "fcntl" fullword
	condition:
		any of them
}
