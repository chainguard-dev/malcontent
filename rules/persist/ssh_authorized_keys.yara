rule ssh_authorized_key : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "Accesses SSH authorized_keys"
  strings:
	$ssh_ = ".ssh" fullword
	$ssh2 = "authorized_keys"
	$not_ssh_client = "SSH_AUTH_SOCK"
  condition:
     all of ($ssh*) and none of ($not*)
}
