rule login_records : suspicious {
	meta:
		description = "accesses historical login records"
	strings:
		$f_lastlog = "/var/log/lastlog" fullword
		$f_utmp = "/var/log/utmp" fullword
		$f_utmpx = "/var/log/utmpx" fullword

		// entries from include/paths.h
		$not_cshell = "_PATH_CSHELL" fullword
		$not_rwho = "_PATH_RWHODIR" fullword
	condition:
		any of ($f*) and none of ($not*)
}

