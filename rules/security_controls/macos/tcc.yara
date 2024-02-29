
rule macos_tcc_db : suspicious {
  meta:
	description = "Accesses the TCC (Transparency, Consent, and Control) database"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2023_trojan_JokerSpy_Python_xcc = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2023_trojan_JokerSpy_Python_xcc_2 = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2023_trojan_JokerSpy_Python_xcc_3 = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
  strings:
    $com_apple_TCC = "com.apple.TCC/TCC.db"
    $not_arc = "WelcomeToArc"
    $not_mdm = "MDMOverrides.plist"
  condition:
    $com_apple_TCC and none of ($not*)
}
