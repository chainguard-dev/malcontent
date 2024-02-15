
rule http_hardcoded_ip : suspicious exfil {
  meta:
	description = "URL pointing to an IP address rather than DNS name"
  strings:
    $ipv4 = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}/
	$metadata = "http://169.254.169.254"
  condition:
	$ipv4 and not $metadata
}