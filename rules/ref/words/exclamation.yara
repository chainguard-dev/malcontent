rule exclamations : notable {
	meta:
		description = "gets very excited"
	strings:
		$exclaim = /[\w ]{0,32} [\w ]{0,32}\!{2,16}/
	condition:
		any of them
}
