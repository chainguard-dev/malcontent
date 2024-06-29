rule password_finder_mimipenguin : critical {
  meta:
    description = "Password finder/dumper, such as MimiPenguin"
    hash_2024_dumpcreds_mimipenguin = "79b478d9453cb18d2baf4387b65dc01b6a4f66a620fa6348fa8dbb8549a04a20"
    hash_2024_dumpcreds_mimipenguin = "3acfe74cd2567e9cc60cb09bc4d0497b81161075510dd75ef8363f72c49e1789"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
  strings:
    $base_apache_temp = "strings /tmp/apache* | grep -E '^Authorization: Basic.+=$" fullword
    $base_apache2 = "apache2.conf" fullword
    $base_gnome_function = "GnomeKeyringPasswordFinder()"
    $base_gnome_keyring = "gnome-keyring"
    $base_gnome_keyring_sed = "sed -rn '/gnome\\-keyring\\-daemon/p'"
    $base_lightdm = "lightdm" fullword
    $base_mimipenguin = /[Mm]imi[Pp]enguin/
    $base_pid_dump = "strings \"/tmp/dump.${pid}\" | grep -E -m 1 '^\\$.\\$.+\\$')\"" fullword
    $base_shadow = "/etc/shadow"
    $base_sshd_config = "sshd_config" fullword
    $base_vsftpd = "vsftpd" fullword
    $extra_finder = /\bFinder\b/
    $extra_password = /\b[Pp]assword\b/
    $ignore_basic_auth_example = /\w+\:[Pp]assword/
  condition:
    5 of ($base_*) and (1 of ($extra_*) and none of ($ignore_*))
}
