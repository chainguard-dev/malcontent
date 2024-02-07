
rule stat : harmless {
	meta:
		description = "Uses libc functions to access filesystem information"
		pledge = "rpath"
	strings:
		$_stat = "_stat"
	condition:
		any of them
}
