rule renovate_mise_registry: override {
  meta:
    description     = "/usr/lib/renovate/dist/data/mise-registry.js"
    hacktool_chisel = "harmless"

  strings:
    $mise_plugins = "mise-plugins/vfox-1password"
    $zprint       = "kkinnear/zprint"

  condition:
    filesize < 300KB and all of them
}
