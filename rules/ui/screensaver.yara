
rule macos_screensaver_engine_ref : notable {
  meta:
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
  strings:
    $pgrep = "ScreenSaverEngine"
    $not_synergy = "_SYNERGY"
  condition:
    $pgrep and none of ($not*)
}
