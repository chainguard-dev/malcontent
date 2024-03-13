
rule JSONEncode {
	meta:
		description = "encodes JSON"
	strings:
		$jsone = "JSONEncode"
		$marshal = "MarshalJSON" fullword
		$npm = "JSON.stringify"
	condition:
		any of them
}
