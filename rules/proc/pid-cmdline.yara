rule proc_stat {
	strings:
		$string = "/proc/%s/cmdline" fullword
		$digit = "/proc/%d/cmdline" fullword
	condition:
		any of them
}

