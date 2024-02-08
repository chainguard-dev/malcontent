rule ref {
	strings:
		$resolv = "/etc/resolv.conf" fullword
	condition:
		any of them
}