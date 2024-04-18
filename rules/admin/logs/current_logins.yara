rule login_records : notable {
	meta:
		description = "accesses current logins"
	strings:
		$f_wtmp = "/var/log/wtmp" fullword
		$f_wtmpx = "/var/log/wtmpx" fullword

		// entries from include/paths.h
		$not_cshell = "_PATH_CSHELL" fullword
		$not_rwho = "_PATH_RWHODIR" fullword
	condition:
		any of ($f*) and none of ($not*)
}
