rule loopback {
	meta:
		description = "uses loopback pseudo-device files"
	strings:
		$ref = "/dev/loop"
	condition:
		any of them
}
