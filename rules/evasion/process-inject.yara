rule ptrace_injector : high {
	meta:
		description = "may inject code into other processes"
	strings:
		$maps = /\/{0,1}proc\/[%{][%}\w]{0,1}\/maps/

		$ptrace = "ptrace" fullword
		$proc = "process" fullword

		$not_qemu = "QEMU_IS_ALIGNED"
		$not_chromium = "CHROMIUM_TIMESTAMP"
		$not_crashpad = "CRASHPAD" fullword
	condition:
		filesize < 64MB and $maps and $ptrace and $proc and none of ($not*)
}
