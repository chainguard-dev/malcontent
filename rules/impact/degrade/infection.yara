rule infection_killer : critical {
	meta:
		description = "kills competing malware infections"
	strings:
		$k_pgrep = "pgrep" fullword
		$k_kill = "kill" fullword
		$c_pkill = "pkill" fullword
		$c_killall = "killall" fullword

		$c_meshagent = "meshagent" fullword
		$c_kdevchecker = "kdevchecker" fullword
		$c_ipv6_addrconfd = "ipv6_addrconfd" fullword
		$c_kworkerr = "kworkerr" fullword
		$c_cpuhelp = "cpuhelp" fullword
		$c_deamon = "deamon" fullword
		$c_ksoftriqd = "ksoftriqd" fullword
		$c_pastebin = "pastebin" fullword
		$c_solr = "solr.sh" fullword
		$c_solrd = "solrd" fullword
		$c_kinsing = "kinsing" fullword
		$c_kdevtmpfsi = "kdevtmpfsi" fullword
		$c_kthreaddk = "kthreaddk" fullword
		$c_linuxsys = "linuxsys" fullword
		$c_rnv2ymcl = "rnv2ymcl" fullword
		$c_skid_x86 = "skid.x86" fullword
		$c_getpty = "getpy.sh" fullword
	condition:
		filesize < 1MB and any of ($k*) and 2 of ($c*)
}
