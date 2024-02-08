
rule protobuf {
	strings:
		$ref = "protobuf" fullword
	condition:
		any of them
}
