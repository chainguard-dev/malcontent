rule osascript_shell_as_admin: medium {
  meta:
    hash_2017_MacOS_AppStore        = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"


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

  strings:
    $osascript = "osascript"
    $hidden    = "hidden answer"
    $assword   = "assword"
    $sudo      = "sudo"

  condition:
    filesize < 10MB and all of them
}
