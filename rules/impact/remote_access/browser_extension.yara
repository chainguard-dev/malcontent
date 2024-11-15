rule chrome_extension_abuser: high {
  meta:
    description = "Chrome extension that accesses all URLs"

  strings:
    $s_all_urls        = "<all_urls>"
    $s_from_webstore   = "from_webstore"
    $s_scriptable_host = "scriptable_host"
    $not_chromium      = "chromium.googlesource.com"

  condition:
    2 of ($s*) and none of ($not*)
}

rule browser_extension_installer: high {
  meta:
    description = "forcibly loads a Chrome extension"

  strings:
    $a_loadExtensionFlag = "--load-extension"
    $a_chrome            = "Chrome"
    $not_chromium        = "CHROMIUM_TIMESTAMP"

  condition:
    all of ($a*) and none of ($not*)
}
