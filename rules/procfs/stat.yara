
rule proc_stat : notable {
	meta:
		description = "gets kernel/system statistics"
	strings:
		$ref = "/proc/stat" fullword
	condition:
		any of them
}
