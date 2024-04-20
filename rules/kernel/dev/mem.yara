rule mem : suspicious {
	meta:
		capability = "CAP_SYS_RAWIO"
		description = "access raw system memory"
	strings:
		$val = "/dev/mem"

		// entries from include/paths.h
		$not_cshell = "_PATH_CSHELL" fullword
		$not_rwho = "_PATH_RWHODIR" fullword
	condition:
		$val and none of ($not*)
}

rule comsvcs_minidump : suspicious {
  meta:
	description = "dump process memory using comsvcs.ddl"
	author = "Florian Roth"
  strings:
	// extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
	$ref = /comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/
  condition:
    any of them
}
