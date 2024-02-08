rule bsd {
	strings:
		$_srand = "_srand" fullword
	condition:
		any of them
}

