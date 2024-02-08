rule proc_stat {
	strings:
		$string = "/proc/%s/stat" fullword
		$digit = "/proc/%d/stat" fullword
	condition:
		any of them
}

