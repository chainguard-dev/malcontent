rule infected : suspicious {
	meta:
		description = "References being 'infected'"
	strings:
		$ref = "infected"
		$ref2 = "INFECTED"
		$ref3 = "infectio"
	condition:
		any of them
}