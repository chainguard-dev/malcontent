
rule proc_self_status : notable {
	meta:
		description = "gets mountinfo associated to this process"
		pledge = "stdio"
	strings:
		$ref = "/proc/self/mountinfo" fullword
	condition:
		any of them
}
