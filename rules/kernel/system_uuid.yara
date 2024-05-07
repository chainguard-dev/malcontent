rule macos_platform_check : notable {
	meta:
		description = "machine unique identifier"
	strings:
		$ref = "IOPlatformUUID" fullword
		$ref2 = "DeviceIDInKeychain"
	condition:
		any of them
}
