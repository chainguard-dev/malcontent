
rule osascript_shell_as_admin : notable {
  strings:
    $do_shell = "do shell script"
    $with_admin = "with administrator privileges"
    $not_successfully_installed = "successfully installed"
    $not_microsoft = "Microsoft Corporation"
  condition:
    $do_shell and $with_admin and none of ($not*)
}
