rule proc_pid_stat {
	meta:
		description = "Accesses process stats using /pid/%d/stat"
	strings:
		$string = "/proc/%s/stat" fullword
		$digit = "/proc/%d/stat" fullword
	condition:
		any of them
}

