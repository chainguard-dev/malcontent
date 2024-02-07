rule bsd {
	strings:
		$_time = "_time" fullword
	condition:
		any of them
}
