
rule semicolon_relative_path : high {
  meta:
    ref = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
    hash_2023_Py_Trojan_NecroBot_0e60 = "0e600095a3c955310d27c08f98a012720caff698fe24303d7e0dcb4c5e766322"
    hash_2023_Unix_Dropper_Mirai_0e91 = "0e91c06bb84630aba38e9c575576b46240aba40f36e6142c713c9d63a11ab4bb"
    hash_2023_Unix_Dropper_Mirai_4d50 = "4d50bee796cda760b949bb8918881b517f4af932406307014eaf77d8a9a342d0"
  strings:
    $semi_relative = /[\/\w]{3,};[ +]{0,8}\.\/\.{0,8}\w{3,}/
  condition:
    any of them
}
