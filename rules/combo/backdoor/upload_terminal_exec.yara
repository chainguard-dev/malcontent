
rule spectralblur_alike : suspicious {
	meta:
		description = "Uploads, provides a terminal, runs program"
	strings:
		$upload = "upload"
		$shell = "shell"
		$tcsetattr = "tcsetattr"
		$execve = "execve"
		$waitpid = "_waitpid"
		$unlink = "_unlink"
		$uname = "_uname"
	condition:
		all of them
}
