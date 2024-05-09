
rule macos_tcc_db : high {
  meta:
    description = "access TCC (Transparency, Consent, and Control) database"
    hash_2018_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
  strings:
    $com_apple_TCC = "com.apple.TCC/TCC.db"
    $not_arc = "WelcomeToArc"
    $not_mdm = "MDMOverrides.plist"
  condition:
    $com_apple_TCC and none of ($not*)
}
