rule omni_ja: override {
  meta:
    description                                      = "omni.ja"
    SECUINFRA_SUS_Unsigned_APPX_MSIX_Installer_Feb23 = "harmless"
    crypto_stealer_names                             = "harmless"

  strings:
    $mozilla_org  = /mozilla\.org/
    $resource_gre = /resource:\/\/gre\//

  condition:
    filesize < 60MB and #mozilla_org > 1000 and #resource_gre > 1000
}
