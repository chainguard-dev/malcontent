
rule creat : notable {
	meta:
		description = "create a new file or rewrite an existing one"
		syscalls = "open"
		ref = "https://man7.org/linux/man-pages/man3/creat.3p.html"
	strings:
		$system = "creat" fullword
	condition:
		all of them in (1500..3000)
}
