
rule npm_sysinfoexfil : suspicious {
	meta:
		description = "exfiltrate system information"
	strings:
		$p1 = "process.platform"
		$p2 = "process.arch"
		$p3 = "process.versions"

		$h = "http.request"

		$post = "POST"
	condition:
		$h and $post and any of ($p*)
}