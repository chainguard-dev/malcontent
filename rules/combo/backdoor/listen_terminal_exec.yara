
rule bpfdoor_alike : suspicious {
	meta:
		description = "Listens, provides a terminal, runs program"
	strings:
		$f_listen = "listen" fullword
		$f_grantpt =  "grantpt"  fullword
		$f_execve = "execve" fullword
		$f_ptmx = "/dev/ptmx"
		$not_sql_db = "sql.DB"
		$not_libc = "getusershell"
	condition:
		all of ($f*) and none of ($not*)
}
