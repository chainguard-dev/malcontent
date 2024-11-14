rule password_finder_mimipenguin: critical {
  meta:
    description                     = "Password finder/dumper, such as MimiPenguin"
    hash_2024_dumpcreds_mimipenguin = "79b478d9453cb18d2baf4387b65dc01b6a4f66a620fa6348fa8dbb8549a04a20"
    hash_2024_dumpcreds_mimipenguin = "3acfe74cd2567e9cc60cb09bc4d0497b81161075510dd75ef8363f72c49e1789"
    hash_2024_enumeration_linpeas   = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $base_lightdm     = "lightdm" fullword
    $base_apache2     = "apache2.conf" fullword
    $base_vsftpd      = "vsftpd" fullword
    $base_shadow      = "/etc/shadow"
    $base_gnome       = "gnome-keyring-da"
    $base_sshd_config = "sshd" fullword

    $extra_finder           = /\bFinder\b/
    $extra_password         = /\b[Pp]assword\b/
    $extra_password2        = /.[^\s]{0,32}-password/
    $extra_proc             = /\/proc\/.{0,3}\/maps/
    $not_basic_auth_example = /\w{0,32}\:[Pp]assword/
    $not_caddy              = "//starting caddy process"
    $not_datadog            = /[Dd]ata[Dd]og/

  condition:
    filesize < 2MB and 3 of ($base*) and any of ($extra*) and none of ($not*)
}

rule password_prompt: medium {
  meta:
    description = "prompts for a password"

  strings:
    $isPasswordVisible = "isPasswordVisible"

  condition:
    filesize < 25MB and any of them
}

rule password_prompt_high: high {
  meta:
    description = "demands a password to be entered"

  strings:
    $must = "password must be entered"

  condition:
    filesize < 25MB and any of them
}

rule verify_password: medium {
  meta:
    description = "verifies a password via unknown means"

  strings:
    $verify = "verifyPassword"

  condition:
    filesize < 10MB and any of them

}
