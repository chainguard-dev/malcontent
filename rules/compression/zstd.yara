
rule zstd {
	meta:
		description = "Zstandard - fast real-time compression algorithm"
	strings:
		$ref = "zstd" fullword
	condition:
		any of them
}
