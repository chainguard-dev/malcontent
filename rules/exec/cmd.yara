rule exec : notable {
	meta:
		description = "executes a command"
	strings:
		$exe_cmd = /[\w:]{0,32}[Ee]xe[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
		$run_cmd = /[\w:]{0,32}[rR]un[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
		$start_cmd = /[\w:]{0,32}[sS]tart[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
		$cmdlist = "cmdlist" fullword
	condition:
		any of them
}
