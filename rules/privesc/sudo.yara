
rule unusual_sudo_commands_value : suspicious {
  meta:
    description = "Unusual sudo commands"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2023_brawl_earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2017_AptorDoc_Bella_AppStore = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
    hash_2023_ciscotools_4247 = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"
  strings:
    $sudo_echo = /sudo echo[\"\%@\-\$\w]{0,32}/
    $sudo_u_echo = /sudo -u [\%@\-\$\w]{2,32} echo/
    $sudo_u_args = /sudo -u [\%\$\{]{1,2}[ \%\$\w\/]{0,32}/
    $sudo_args =/sudo %@\"\%@\-\$\w]/
    $sudo_no_sleep = /[\|\"\w\-]{0,16}sudo -S[ \%\$\w\/]{1,32}/
    $sudo_bash = /sudo bash[\"\%@\-\$\w]{1,64}/
    $not_needs_root = "needs to be run as root"
    $not_sudo_example = "'sudo %@'"
  condition:
    any of ($sudo*) and none of ($not*)
}
