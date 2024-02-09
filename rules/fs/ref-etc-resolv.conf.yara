rule etc_resolv_conf {
	strings:
		$resolv = "/etc/resolv.conf" fullword
	condition:
		any of them
}