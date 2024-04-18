rule usr_sbin_telnetd : suspicious {
	meta:
		description = "References /usr/sbin/telnetd"
	strings:
		$ref = "/usr/sbin/telnetd"

		// ignore lists of busybox hard links
		$not_dos2unix = "/usr/bin/dos2unix"
		$not_setfont = "/usr/sbin/setfont"

	condition:
		$ref and none of ($not*)
}