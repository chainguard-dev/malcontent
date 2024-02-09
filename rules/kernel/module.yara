rule lkm {
	meta:
		description = "Contains a Linux kernel module"
	strings:
		$vergmagic = "vermagic="
		$srcversion = "srcversion="
	condition:
		all of them
}
