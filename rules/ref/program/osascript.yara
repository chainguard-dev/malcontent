
rule osascript_caller : notable {
  meta:
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2011_bin_kc_dump = "58a1dbe5cbb1ea38dbc57b6d2cf8c0b03c38a9ed858d7390aca590c2ac017f6f"
    hash_2011_Twitterrific_bin_bop = "d2398b764758e23fcac6e29358f36d79e32cdea05c99d95e8423fb0c6943a291"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $o_osascript = "osascript" fullword
    $o_osascript_e = "osascript -e"
    $o_display_dialog = "display dialog"
    $o_with_hidden_answer = "with hidden answer"
    $o_default = "default button \""
  condition:
    any of ($o*)
}
