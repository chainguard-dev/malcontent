rule firefox_cookies : suspicious {
	meta:
		description = "Accesses Firefox cookies"
	strings:
		$firefox = "Firefox"
		$cookie = "cookie"
		$cookie2 = "Cookie"
		$sqlite = "sqlite"
	condition:
		$firefox and ($sqlite and any of ($cookie*))
}
