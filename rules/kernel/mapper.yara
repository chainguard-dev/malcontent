rule mapper {
	meta:
		description = "uses the device mapper framework"
		ref = "https://en.wikipedia.org/wiki/Device_mapper"
	strings:
		$ref = "/dev/mapper"
	condition:
		any of them
}
