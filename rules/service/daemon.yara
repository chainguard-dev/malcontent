
rule daemon {
	meta:
		description = "Run as a background daemon"
	strings:
		$ref = "daemon" fullword
	condition:
		all of them
}