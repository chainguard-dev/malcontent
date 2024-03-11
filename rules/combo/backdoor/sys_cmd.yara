rule multiple_sys_commands : suspicious {
  meta:
    hash_2022_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2023_articles_https_pberba_github_io_security_2022_02_07_linux_threat_hunting_for_persistence_systemd_generators = "8c227f67a16162ffd5b453a478ced2950eba4cbe3b004c5cc935fb9551dc2289"
    hash_2023_articles_https_www_crowdstrike_com_blog_how_to_hunt_for_decisivearchitect_and_justforfun_implant = "cc3d0e46681b416ef79e729c9f766d5e56f760904caba367f30df3cafae44f75"
    hash_2023_BPFDoor_07ec = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
    hash_2023_BPFDoor_17dd = "17ddd405e4ed78129808dcf5a3381568d8f74878ca0535249cfb31340950ea85"
    hash_2023_BPFDoor_2e0a = "2e0aa3da45a0360d051359e1a038beff8551b957698f21756cfc6ed5539e4bdb"
    hash_2023_BPFDoor_340f = "340fec891eff2bbeccbef054a6b7e7e04fc09cf3b3b5fdf06accbd193a03b453"
  strings:
    $cron = "/usr/sbin/cron"
    $rsyslog = "/usr/sbin/rsyslogd"
    $systemd = "systemd/systemd"
    $auditd = "auditd" fullword
    $sshd = "/usr/sbin/sshd"
    $busybox = "/bin/busybox"
    $sdpd = "/usr/sbin/sdpd"
    $gam = "/usr/libexec/gam_server"
  condition:
    2 of them
}
