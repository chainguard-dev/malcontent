rule home_path : notable {
	meta:
		description = "References paths within /home"
	strings:
		$home = /\/home\/[%\w\.\-\/]{0,64}/
		$home_build = "/home/build"
	condition:
		$home and not $home_build
}