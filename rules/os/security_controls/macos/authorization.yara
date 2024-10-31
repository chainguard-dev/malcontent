
rule system_privilege_admin : medium {
  meta:
    hash_2015_MacOS_EasyDoc_Converter = "896c863de42f4ec63a53657ecc5cfbcc780ac60149564e1be40e3899851571bb"
    hash_2020_EvilQuest_patch = "5a024ffabefa6082031dccdb1e74a7fec9f60f257cd0b1ab0f698ba2a5baca6b"
    hash_2020_FinSpy_installer = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"
  strings:
    $admin = "system.privilege.admin"
    $com_apple = "com.apple."
  condition:
    $admin and not $com_apple
}
