rule bsd_rand {
	strings:
		$_rand = "_rand" fullword
	condition:
		any of them
}

