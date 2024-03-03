rule proc_status : notable {
	meta:
		description = "Accesses the status fields for other processes"
	strings:
		$string = "/proc/%s/status" fullword
		$digit = "/proc/%d/status" fullword
		$python = "/proc/{}/status" fullword
	condition:
		any of them
}
