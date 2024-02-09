rule bsd_srand {
	strings:
		$_srand = "_srand" fullword
	condition:
		any of them
}

