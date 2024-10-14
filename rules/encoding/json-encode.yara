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

rule json_dumps : low {
	meta:
		description = "encodes JSON"
		filetypes = "py"
	strings:
		$jsone = "json" fullword
		$marshal = "dumps" fullword
		$import = "import" fullword
	condition:
		filesize < 8KB and all of them
}
