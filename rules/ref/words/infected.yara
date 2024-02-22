rule infected : suspicious {
	meta:
		description = "References being 'infected'"
	strings:
		$ref = "infected"
		$ref2 = "INFECTED"
	condition:
		any of them
}