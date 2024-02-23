rule hardcoded_hostport2 : high {
  meta:
	description = "Contains hardcoded IP:port address"
  strings:
    $ipv4 = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}:\d{2,5}/ fullword
  condition:
    any of ($ip*)
}

