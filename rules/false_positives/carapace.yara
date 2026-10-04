rule carapace_bin: override {
  meta:
    description               = "/usr/bin/carapace: the anchor completer offers Anchor's debug cluster URL as a completion value"
    http_hardcoded_ip_dev_shm = "low"

  strings:
    $module = /github\.com\/carapace-sh\/carapace-bin/
    $anchor = /github\.com\/carapace-sh\/carapace-bin\/pkg\/actions\/tools\/anchor/

  condition:
    filesize > 30MB and filesize < 150MB and all of them
}
