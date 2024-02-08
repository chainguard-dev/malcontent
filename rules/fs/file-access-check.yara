
rule access : harmless {
	meta:
		description = "Uses libc functions to access filesystem information"
	strings:
		$_access = "_access" fullword
	condition:
		any of them
}
