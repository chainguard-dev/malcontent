rule slack_storage: high {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "access Slack Storage files"

  strings:
    $ref = "/Slack/storage"

  condition:
    all of them
}

rule slack_leveldb: high {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "accesses Slack data"

  strings:
    $ref  = "Slack" fullword
    $ref2 = "leveldb" fullword

    $d_app    = "Application Support" fullword
    $d_config = ".config" fullword

    // unrelated - https://github.com/gitleaks/gitleaks
    $not_gitleaks = "gitleaks" fullword

  condition:
    all of ($ref*) and any of ($d*) and none of ($not*)
}
