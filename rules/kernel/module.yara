rule lkm : notable {
	meta:
		description = "Contains a Linux kernel module"
		capability = "CAP_SYS_MODULE"
	strings:
		$vergmagic = "vermagic="
		$srcversion = "srcversion="
	condition:
		all of them
}

rule delete_module : notable {
	meta:
		description = "Unload Linux kernel module"
		syscall = "delete_module"
		capability = "CAP_SYS_MODULE"
	strings:
		$ref = "delete_module" fullword
	condition:
		all of them
}
