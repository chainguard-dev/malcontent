rule tls_get_addr {
	meta:
		description = "Uses glibc thread local storage"
		ref = "https://chao-tic.github.io/blog/2018/12/25/tls"
	strings:
		$val = "__tls_get_addr" fullword
	condition:
		any of them
}