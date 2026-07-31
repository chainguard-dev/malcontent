rule password_finder_mimipenguin: critical {
  meta:
    description = "Password finder/dumper, such as MimiPenguin"

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
    $not_basic_auth_example = /\:[Pp]assword\b/
    $not_caddy              = "//starting caddy process"
    $not_datadog            = /[Dd]ata[Dd]og/
    $not_vim1               = "\" Vim support file to detect file types"
    $not_vim2               = "\" Maintainer:           The Vim Project <https://github.com/vim/vim>"
    $not_vim3               = "@vim.org>"

  // $extra_password matches inside $not_basic_auth_example, so a single user:password
  // example used to exempt the whole file, $extra_proc and $extra_password2 included.
  // Discount it from $extra_password by occurrence count only; the other extras are
  // unrelated to a basic-auth example and the other $nots stay presence checks.
  // $not_basic_auth_example carries the trailing \b that $extra_password has, and drops
  // its leading \w{0,32}, so one example yields exactly one match on each side.

  condition:
    filesize < 2MB and 3 of ($base*) and (any of ($extra_finder, $extra_password2, $extra_proc) or #extra_password > #not_basic_auth_example) and none of ($not_caddy, $not_datadog, $not_vim1, $not_vim2, $not_vim3)
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
