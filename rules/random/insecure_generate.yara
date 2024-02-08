rule bsd {
	strings:
		$_rand = "_rand" fullword
	condition:
		any of them
}

