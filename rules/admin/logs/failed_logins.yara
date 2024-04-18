rule failed_logins : suspicious {
	meta:
		description = "accesses failed logins"
	strings:
		$f_wtmp = "/var/log/btmp" fullword

		// entries from include/paths.h
		$not_cshell = "_PATH_CSHELL" fullword
		$not_rwho = "_PATH_RWHODIR" fullword
	condition:
		any of ($f*) and none of ($not*)
}
