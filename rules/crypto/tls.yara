rule tls {
	strings:
		$go = "crypto/tls"
		$tlsversion = "TLSVersion"
		$tls123 = "TLS13"
	condition:
		any of them
}
