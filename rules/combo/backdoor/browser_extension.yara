rule chrome_extension_abuser: high {
  meta:
    hash_2017_CoinThief = "7f32fdcaefee42f93590f9490ab735ac9dfeb22a951ff06d721145baf563d53b"

  strings:
    $s_all_urls        = "<all_urls>"
    $s_from_webstore   = "from_webstore"
    $s_scriptable_host = "scriptable_host"
    $not_chromium      = "chromium.googlesource.com"

  condition:
    2 of ($s*) and none of ($not*)
}

rule browser_extension_installer: high {
  strings:
    $a_loadExtensionFlag = "--load-extension"
    $a_chrome            = "Chrome"
    $not_chromium        = "CHROMIUM_TIMESTAMP"

  condition:
    all of ($a*) and none of ($not*)
}
