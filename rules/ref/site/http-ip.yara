
rule http_hardcoded_ip : suspicious exfil {
  meta:
	description = "URL pointing to an IP address rather than DNS name"
  strings:
    $ipv4 = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}[:\/\w\?]{0,32}/
	$not_metadata = "http://169.254.169.254"
	$not_100 = "http://100.100.100"
	$not_11 = "http://11.11.11"
	$not_192 = "http://192.168"
  condition:
    $ipv4 and none of ($not*)
}
