rule bsd {
	strings:
		$_sleep = "_sleep" fullword
	condition:
		any of them
}

