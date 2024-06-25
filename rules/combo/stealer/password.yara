
rule password_finder_mimipenguin : critical {
  meta:
    description = "Password finder/dumper, such as MimiPenguin"
    hash_2024_dumpcreds_mimipenguin = "79b478d9453cb18d2baf4387b65dc01b6a4f66a620fa6348fa8dbb8549a04a20"
    hash_2024_dumpcreds_mimipenguin = "3acfe74cd2567e9cc60cb09bc4d0497b81161075510dd75ef8363f72c49e1789"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
  strings:
    $lightdm = "lightdm" fullword
    $apache2 = "apache2.conf" fullword
    $vsftpd = "vsftpd" fullword
    $shadow = "/etc/shadow"
    $gnome = "gnome-keyring-daemon"
    $password = "password"
    $finder = "Finder"
    $sshd_config = "sshd_config" fullword
  condition:
    5 of them
}
