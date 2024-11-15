rule system_privilege_admin: medium {
  meta:
    description = "executes with admin privileges"

  strings:
    $admin     = "system.privilege.admin"
    $com_apple = "com.apple."

  condition:
    $admin and not $com_apple
}
