
rule npm_sysinfoexfil : suspicious {
	meta:
		description = "exfiltrate system information"
	strings:
		$proc1 = "process.platform"
		$proc2 = "process.arch"
		$proc3 = "process.versions"

		$h = "http.request"

		$post = "POST"
	condition:
		$h and $post and any of ($proc*)
}