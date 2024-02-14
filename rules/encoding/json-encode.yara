
rule JSONEncode {
	strings:
		$jsone = "JSONEncode"
		$marshal = "MarshalJSON" fullword
	condition:
		any of them
}
