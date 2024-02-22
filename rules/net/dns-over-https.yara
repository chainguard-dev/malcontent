rule doh_refs : notable {
	meta:
		description = "Supports DNS (Domain Name Service) over HTTPS"
	strings:
		$doh_Provider = "doh.Provider"
		$DnsOverHttps = "DnsOverHttps"
		$contentType = "application/dns-message"
		$dnspod = "dnspod"
	condition:
		any of them
}
