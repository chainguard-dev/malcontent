rule home_path : notable {
	meta:
		description = "peferences path within /home"
	strings:
		$home = /\/home\/[%\w\.\-\/]{0,64}/
		$not_build = "/home/build"
		$not_runner = "/home/runner"
	condition:
		$home and none of ($not*)
}