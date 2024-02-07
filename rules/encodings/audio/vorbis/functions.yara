
rule vorbisdsp {
	strings:
		$vorbisdsp = "vorbisdsp"
	condition:
		any of them
}
