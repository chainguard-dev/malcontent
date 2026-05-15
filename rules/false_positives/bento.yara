rule bento_bin: override {
  meta:
    description         = "bento"
    CAPE_Nitrogenloader = "harmless"

  strings:
    $go_module = "github.com/warpstreamlabs/bento/cmd/bento"
    $go_pkg    = "github.com/warpstreamlabs/bento/public/service"

  condition:
    filesize > 200MB and filesize < 300MB and all of them
}
