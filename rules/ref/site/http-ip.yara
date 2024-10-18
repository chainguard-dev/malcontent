rule http_hardcoded_ip : high exfil {
  meta:
    description = "hardcoded IP address within a URL"
    hash_2023_Merlin_48a7 = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"
    hash_2023_Multios_Trojan_WellMess_bce8 = "bce8ba5b7e6598c15c5ec258199e148272087fde2cd0690ed9b42ba89f2aacea"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
  strings:
    $ipv4 = /https*:\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}[:\/\w\-\?\.]{0,32}/
    $not_metadata = "http://169.254.169.254"
    $not_100 = "http://100.100.100"
    $not_11 = "http://11.11.11"
    $not_192 = "http://192.168"
	$not_169 = "http://169.254"
  condition:
    $ipv4 and none of ($not*)
}
