
rule accept {
	meta:
		description = "accept a connection on a socket"
	strings:
		$socket = "socket" fullword
		$accept = "accept" fullword
	condition:
		all of them
}
