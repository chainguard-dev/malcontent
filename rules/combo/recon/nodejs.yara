
rule npm_sysinfoexfil : high {
	meta:
		description = "may gather and exfiltrate system information"
	strings:
		$proc1 = "process.platform"
		$proc2 = "process.arch"
		$proc3 = "process.versions"

		$h = "http.request"

		$post = "POST"
	condition:
		filesize < 32MB and $h and $post and any of ($proc*)
}