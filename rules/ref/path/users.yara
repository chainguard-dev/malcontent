rule home_path : notable {
	meta:
		description = "references path within /Users"
	strings:
		$ref = /\/Users\/[%\w\.\-\/]{0,64}/
	condition:
		$ref
}