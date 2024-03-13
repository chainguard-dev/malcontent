rule kmod : suspicious {
	meta:
		description = "includes Linux kernel module source code"
	strings:
		$ref = "<linux/kmod.h>"
	condition:
		any of them
}