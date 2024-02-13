rule dylib : harmless {
	meta:
		description = "makes use of dynamic libraries"
	strings:
		$dlopen = "dlopen" fullword
		$dlclose = "dlclose" fullword
	condition:
		any of them
}
