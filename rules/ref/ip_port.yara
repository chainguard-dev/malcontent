rule hardcoded_hostport2 : high {
  meta:
	description = "hardcoded IP:port destination"
  strings:
    $ipv4 = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
	$not_ssdp = "239.255.255.250:1900"
  condition:
    any of ($ip*) and none of ($not*)
}

