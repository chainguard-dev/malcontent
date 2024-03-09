rule agent : notable {
	meta:
		description = "References an 'agent'"
	strings:
		$ref = /[a-zA-Z_]{0,16}agent/ fullword
		$ref2 = /agent[a-zA-Z_]{0,16}/ fullword
	condition:
		any of them
}
