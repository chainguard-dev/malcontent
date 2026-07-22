rule portainer: override {
  meta:
    description     = "/usr/bin/portainer"
    hacktool_chisel = "harmless"

  strings:
    $portainer_module = "github.com/portainer/portainer"
    $portainer_chisel = "github.com/portainer/portainer/api/chisel"

  condition:
    filesize < 200MB and all of them
}
