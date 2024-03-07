rule infected : notable {
	meta:
		description = "References being 'infected'"
	strings:
		$ref = "infected"
		$ref2 = "INFECTED"
	condition:
		any of them
}

rule infection : notable {
	meta:
		description = "References 'infectio'"
	strings:
		$ref3 = "infectio"
	condition:
		any of them
}