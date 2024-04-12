rule systemctl_calls_val : notable {
  meta:
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2020_Rekoobe_egiol = "6fc03c92dee363dd88e50e89062dd8a22fe88998aff7de723594ec916c348d0a"
    hash_2020_CoinMiner_nbtoz = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2023_Linux_Malware_Samples_ee0e = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
    hash_2023_articles_https_www_intezer_com_blog_malware_analysis_elf_malware_analysis_101_part_3_advanced_analysis = "f63e4d0af48f819b71179109ef7bbeb9029e56e97b288ae7142897143c32fa0b"
    hash_2023_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2023_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
  strings:
    $systemctl_cmd = /systemctl (daemon-reload|reload|enable|stop|disable|restart|start)[\w _-]{0,32}/
  condition:
    any of them
}
