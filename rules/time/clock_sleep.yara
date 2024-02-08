rule bsd {
	strings:
		$_sleep = "_sleep" fullword
		$_usleep = "_usleep" fullword
	condition:
		any of them
}

