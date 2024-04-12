rule firefox_history : suspicious {
	meta:
		description = "Accesses Firefox form history, which contains passwords"
	strings:
		$firefox = "Firefox"
		$formhist = "formhistory.sqlite"
	condition:
		all of them
}
