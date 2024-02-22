
rule reuseport : notable {
	meta:
		description = "able to listen and dial from the same TCP/UDP port"
	strings:
		$go = "go-reuseport"
		$so_readdr = "SO_REUSEADDR"
		$so_report = "SO_REUSEPORT"
	condition:
		any of them
}
