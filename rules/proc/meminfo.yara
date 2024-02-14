
rule proc_meminfo : notable {
	meta:
		description = "get memory info"
	strings:
		$ref = "/proc/meminfo" fullword
	condition:
		any of them
}
