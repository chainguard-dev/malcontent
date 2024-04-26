
rule tempdir {
	meta:
		description = "looks up location of temp directory"
		pledge = "wpath"
	strings:
		$gettempdir = "gettempdir" fullword
		$tempdir = "TEMPDIR" fullword
		$tmpdir = "TMPDIR" fullword
		$cocoa = "NSTemporaryDirectory" fullword
	condition:
		any of them
}
