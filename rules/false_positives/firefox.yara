rule omni_ja: override {
  meta:
    description                                      = "omni.ja"
    SECUINFRA_SUS_Unsigned_APPX_MSIX_Installer_Feb23 = "harmless"

  strings:
    $firefox = "firefox"

  condition:
    filesize < 50MB and #firefox > 3000
}
