rule mise: override {
  meta:
    description           = "/usr/bin/mise"
    hacktool_chisel       = "harmless"
    polkit_pkexec_exploit = "harmless"

  strings:
    $jdx_mise    = "jdx/mise"
    $mise_config = "~/.config/mise/config.toml"

  condition:
    filesize > 50MB and filesize < 150MB and all of them
}
