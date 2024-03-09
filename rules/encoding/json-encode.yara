
rule JSONEncode {
	strings:
		$jsone = "JSONEncode"
		$marshal = "MarshalJSON" fullword
		$npm = "JSON.stringify"
	condition:
		any of them
}
