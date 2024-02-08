rule icmp {
	strings:
		$ICMP = "ICMP" fullword
		$icmp = "icmp" fullword
	condition:
		any of them
}

rule phrases {
	strings:
		$echo_request = "Echo Request" fullword
		$source_quench = "Source Quench" fullword
		$echo_reply = "Echo Reply" fullword
	condition:
		2 of them
}