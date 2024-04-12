rule firefox_cookies : suspicious {
	meta:
		description = "Accesses Firefox cookies"
	strings:
		$firefox = "Firefox"
		$cookie = "cookies.sqlite"
	condition:
		all of them
}
