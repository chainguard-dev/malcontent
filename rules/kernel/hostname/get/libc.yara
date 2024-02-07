
rule gethostname {
	strings:
		$gethostname = "gethostname"
	condition:
		any of them
}
