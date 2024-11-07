rule virtualbox_override: override {
  meta:
    description   = "VirtualBox"
    backdoor_caps = "low"

  strings:
    $ref = "GROUP_DEV_VMM_BACKDOOR"

  condition:
    filesize < 1MB and any of them
}
