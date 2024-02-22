rule etc_path {
	meta:
		description = "References /etc/resolv.conf (DNS resolver configuration)"
	strings:
		$resolv = "/etc/resolv.conf"
	condition:
		any of them
}