rule osascript_shell_as_admin: medium {
  meta:
    description = "uses osascript with admin privileges"
    filetypes   = "scpt,scptd"

  strings:
    $do_shell                   = "do shell script"
    $with_admin                 = "with administrator privileges"
    $not_successfully_installed = "successfully installed"
    $not_microsoft              = "Microsoft Corporation"

  condition:
    $do_shell and $with_admin and none of ($not*)
}

rule osascript_fake_password: critical {
  meta:
    description = "uses osascript to prompt for a sudo password"
    filetypes   = "scpt,scptd"

  strings:
    $osascript = "osascript"
    $hidden    = "hidden answer"
    $assword   = "assword"
    $sudo      = "sudo"

  condition:
    filesize < 10MB and all of them
}
