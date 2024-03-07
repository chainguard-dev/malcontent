rule pseudoterminal_tunnel : critical {
	meta:
		description = "accesses pseudoterminals and sets up a tunnel"
	strings:
		$pty = "creack/pty" fullword
		$ptsname = "ptsname" fullword

		$t = "tunnel" fullword
		$t2 = "TUNNEL" fullword
	condition:
		any of ($p*) and any of ($t*)
}
