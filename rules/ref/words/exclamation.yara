rule exclamations : notable {
	meta:
		description = "gets very excited"
	strings:
		// trying to match multiple words
		$exclaim = /[\w ]{2,32} [\w ]{2,32}\!{2,16}/
	condition:
		any of them
}
