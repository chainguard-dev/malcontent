rule register_kprobe : notable {
	meta:
		description = "registers a kernel probe (possibly kernel module)"
	strings:
		$ref = "register_kprobe"
	condition:
		any of them
}

