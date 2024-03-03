rule proc_maps : notable {
	meta:
		description = "Accesses process memory maps using /pid/%d/maps"
	strings:
		$string = "/proc/%s/maps" fullword
		$digit = "/proc/%d/maps" fullword
		$python = "/proc/{}/maps" fullword
	condition:
		any of them
}

