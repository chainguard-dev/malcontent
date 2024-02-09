rule bsd_time : harmless {
	strings:
		$_time = "_time" fullword
	condition:
		any of them
}
