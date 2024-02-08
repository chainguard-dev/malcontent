
rule connect {
	strings:
		$connect = "_connect" fullword
		$connectx = "_connectx" fullword
	condition:
		any of them
}
