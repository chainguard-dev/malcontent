rule system_privilege_admin: medium {
  meta:
    hash_2020_EvilQuest_patch = "5a024ffabefa6082031dccdb1e74a7fec9f60f257cd0b1ab0f698ba2a5baca6b"

  strings:
    $admin     = "system.privilege.admin"
    $com_apple = "com.apple."

  condition:
    $admin and not $com_apple
}
