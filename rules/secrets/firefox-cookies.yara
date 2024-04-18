rule firefox_cookies : suspicious {
	meta:
		description = "access Firefox cookies"
	strings:
		$firefox = "Firefox"
		$fcookie = "cookies.sqlite"

		$not_chromium = "CHROMIUM_TIMESTAMP"
	condition:
		all of ($f*) and none of ($not*)
}
