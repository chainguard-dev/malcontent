rule proc_maps : notable {
	meta:
		description = "access process memory maps"
	strings:
		$string = "/proc/%s/maps" fullword
		$digit = "/proc/%d/maps" fullword
		$python = "/proc/{}/maps" fullword
	condition:
		any of them
}

