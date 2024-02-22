
rule proc_mounts : notable {
	meta:
		description = "Parses active mounts (/proc/mounts"
		pledge = "stdio"
	strings:
		$ref = "/proc/mounts" fullword
	condition:
		any of them
}
