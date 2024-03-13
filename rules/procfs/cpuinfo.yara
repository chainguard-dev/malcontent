
rule proc_cpuinfo : notable {
	meta:
		description = "get CPU info"
	strings:
		$ref = "/proc/cpuinfo" fullword
	condition:
		any of them
}
