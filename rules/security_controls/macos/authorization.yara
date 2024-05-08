
rule system_privilege_admin : notable {
  strings:
    $admin = "system.privilege.admin"
    $com_apple = "com.apple."
  condition:
    $admin and not $com_apple
}
