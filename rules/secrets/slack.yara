rule slack_storage : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "Accesses Slack Storage files"
  strings:
	$ref = "/Slack/storage"
  condition:
    all of them
}
