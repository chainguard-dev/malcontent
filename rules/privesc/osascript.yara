rule osascript_shell_as_admin: medium {
  meta:
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2017_MacOS_AppStore          = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
    hash_2018_MacOS_SpellingChecker   = "a9a7a1c48cd1232249336749f4252c845ce68fd9e7da85b6da6ccbcdc21bcf66"

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
