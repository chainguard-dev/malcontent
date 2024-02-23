rule etc_resolv_conf {
	meta:
		description = "References /etc/resolv.conf (DNS resolver configuration)"
	strings:
		$resolv = "/etc/resolv.conf"
	condition:
		any of them
}