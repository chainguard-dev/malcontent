rule hardcoded_ip_port : high {
  meta:
	description = "hardcoded IP:port destination"
  strings:
    $ipv4 = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
	$not_ssdp = "239.255.255.250:1900"
	$not_2181 = "10.101.203.230:2181"
	$not_meta = "169.254.169.254:80"
	$not_vnc = "10.10.10.10:5900"
	$not_azure_pgsql = "20.66.25.58:5432"
  condition:
    any of ($ip*) and none of ($not*)
}

