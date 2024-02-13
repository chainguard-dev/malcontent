rule _reboot : harmless {
	meta:
		capability = "CAP_SYS_BOOT"
		description = "reboot system"
	strings:
		$ref = "_reboot" fullword
		$not_master = "master_reboot"
	condition:
		$ref and none of ($not*)
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

