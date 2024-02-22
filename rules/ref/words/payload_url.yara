rule payload_url : suspicious {
	meta:
		description = "References a 'payload URL'"
	strings:
		$ref = "payload_url" fullword
		$ref2 = "payload url" fullword
		$ref3 = "payload URL" fullword
	condition:
		any of them
}