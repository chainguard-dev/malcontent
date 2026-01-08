rule bento_bin: override {
  meta:
    description         = "bento"
    CAPE_Nitrogenloader = "harmless"

  strings:
    $golang = /(google.){0,1}golang.org/
    $repo   = "github.com/warpstreamlabs/bento"

  condition:
    filesize < 250MB and #golang > 38000 and #repo > 21000
}
