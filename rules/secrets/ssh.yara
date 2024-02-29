rule ssh_folder : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "Accesses SSH configuration files and/or keys"
  strings:
	$ref = ".ssh" fullword
  condition:
    all of them
}
