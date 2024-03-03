rule proc_cmdline : notable {
	meta:
		description = "Accesses the command-line of other processes"
	strings:
		$string = "/proc/%s/cmdline" fullword
		$digit = "/proc/%d/cmdline" fullword
		$python = "/proc/{}/cmdline" fullword
	condition:
		any of them
}

