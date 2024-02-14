
rule http_hardcoded_ip : suspicious exfil {
  meta:
	description = "URL pointing to an IP address rather than DNS name"
  strings:
    $ipv4 = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}/
  condition:
    any of them
}