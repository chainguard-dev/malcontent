
rule unusual_sudo_commands_value : notable {
  meta:
    description = "Unusual sudo commands"
  strings:
    $sudo_echo = /sudo echo[ \"\%@\-\$\w\\\.\=]{0,48}/
    $sudo_u_echo = /sudo -u [ \%@\-\$\w]{2,32} echo/
    $sudo_u_args = /sudo -u [\%\$\{\}]{1,2}[ \%\$\w\/]{0,32}/
    $sudo_args = /sudo %@\"\%@\-\$\w]/
    $sudo_no_sleep = /[\|\"\w\-]{0,16}sudo -S[ \%\$\w\/]{1,32}/
    $sudo_bash = /sudo bash[\"\%@\-\$\w]{1,64}/
    $not_needs_root = "needs to be run as root"
    $not_sudo_example = "'sudo %@'"
    $not_bun_example = "<cyan>sudo"
    $not_bun_example2 = "[36msudo"
  condition:
    any of ($sudo*) and none of ($not*)
}
