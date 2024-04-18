rule ssh_folder : notable {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "accesses SSH configuration and/or keys"
  strings:
	$ref = /[\$\%\{\}\w\/]{0,16}\.ssh[\w\/]{0,16}/ fullword
  condition:
    all of them
}