
rule unusual_sudo_commands_value : medium {
  meta:
    description = "Unusual sudo commands"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2018_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
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
