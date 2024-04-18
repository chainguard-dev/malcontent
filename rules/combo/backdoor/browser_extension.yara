rule chrome_extension_abuser : suspicious {
  meta:
    hash_2014_CoinThief = "7f32fdcaefee42f93590f9490ab735ac9dfeb22a951ff06d721145baf563d53b"
  strings:
    $s_all_urls = "<all_urls>"
    $s_from_webstore = "from_webstore"
    $s_scriptable_host = "scriptable_host"

	$not_chromium = "chromium.googlesource.com"
  condition:
    2 of ($s*) and none of ($not*)
}

rule browser_extension_installer : suspicious {
  meta:
    hash_2017_GoPhoto = "a4d8367dc2df3a8539b9baf8ee48d09f5a8e9f9d2d58431909de0bb0816464a0"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
  strings:
    $a_loadExtensionFlag = "--load-extension"
    $a_chrome = "Chrome"

	$not_chromium = "CHROMIUM_TIMESTAMP"
 condition:
    all of ($a*) and none of ($not*)
}