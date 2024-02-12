rule block_devices {
	meta:
		description = "works with block devices"
	strings:
		$ref = "/sys/block/"
		$ref2 = "/sys/dev/block/"
	condition:
		any of them
}
