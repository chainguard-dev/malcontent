
rule miner_kvryr_stak_alike : suspicious {
	meta:
		description = "Uploads, provides a terminal, runs program"
	strings:
		$upload = "upload"
		$shell = "shell"
		$tcsetattr = "tcsetattr"
		$execve = "execve"
	condition:
		all of them
}
