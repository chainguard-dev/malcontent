rule home_path : notable {
	meta:
		description = "References paths within /home"
	strings:
		$resolv = /\/home\/[%\w\.\-\/]{0,64}/
	condition:
		any of them
}