rule dylib {
	strings:
		$dlopen = "_dlopen" fullword
	condition:
		any of them
}
