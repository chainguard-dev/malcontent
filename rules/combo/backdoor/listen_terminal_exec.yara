
rule bpfdoor_alike : suspicious {
	meta:
		description = "Listens, provides a terminal, runs program"
	strings:
		$listen = "listen" fullword
		$grantpt =  "grantpt"  fullword
		$execve = "execve" fullword
	condition:
		all of them
}
