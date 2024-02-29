rule macos_cookies : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "Accesses macOS Cookie files"
  strings:
	$ref = "/Library/Cookies"
	$ref2 = ".binarycookies"
  condition:
    any of them
}

rule chrome_cookies : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "Accesses Google Chrome Cookie files"
  strings:
	$ref = "/Google/Chrome"
	$ref2 = "/Cookies"
  condition:
    all of them
}

rule slack_cookies : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "Accesses Slack Cookie files"
  strings:
	$ref = "/Slack"
	$ref2 = "/Cookies"
  condition:
    all of them
}
