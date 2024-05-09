
rule kmem : high {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "access raw kernel memory"
	strings:
		$val = "/dev/kmem"

		// entries from include/paths.h
		$not_cshell = "_PATH_CSHELL" fullword
		$not_rwho = "_PATH_RWHODIR" fullword		
	condition:
		$val and none of ($not*)
}
