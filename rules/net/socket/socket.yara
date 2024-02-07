
rule socket {
	strings:
		$socket = "socket" fullword
	condition:
		any of them
}
