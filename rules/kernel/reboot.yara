
rule reboot {
	meta:
		capability = "CAP_SYS_BOOT"
		description = "reboot system"
	strings:
		$ref = "reboot" fullword
		$not_daily = "daily" fullword
	condition:
		$ref and none of ($not*)
}

rule _reboot {
	meta:
		capability = "CAP_SYS_BOOT"
		description = "reboot system"
	strings:
		$ref = "_reboot" fullword
	condition:
		$ref
}

rule kexec_load {
	meta:
		capability = "CAP_SYS_BOOT"
		description = "load a new kernel for later execution"
	strings:
		$ref = "kexec_load" fullword
		$ref2 = "kexec_file_load" fullword
	condition:
		any of them
}

