rule firefox_history : suspicious {
	meta:
		description = "access Firefox form history, which contains passwords"
	strings:
		$firefox = "Firefox"
		$formhist = "formhistory.sqlite"

		$not_chromium = "CHROMIUM_TIMESTAMP"
	condition:
		all of ($f*) and none of ($not*)
}
