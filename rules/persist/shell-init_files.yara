rule etc_shell_init_references {
  meta:
    hash_2020_CoinMiner_nbtoz = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2020_trojan_miner_cucnl = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
    hash_2023_articles_https_www_intezer_com_blog_malware_analysis_elf_malware_analysis_101_part_3_advanced_analysis = "f63e4d0af48f819b71179109ef7bbeb9029e56e97b288ae7142897143c32fa0b"
    hash_2023_articles_https_www_intezer_com_blog_research_kaiji_new_chinese_linux_malware_turning_to_golang = "a748bf68a26573a76505c0ecbdd32fa21b48a705e24213885239d1e8527dd15b"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_Unix_Malware_Kaiji_3e68 = "3e68118ad46b9eb64063b259fca5f6682c5c2cb18fd9a4e7d97969226b2e6fb4"
    hash_2023_Unix_Malware_Kaiji_f4a6 = "f4a64ab3ffc0b4a94fd07a55565f24915b7a1aaec58454df5e47d8f8a2eec22a"
  strings:
    $etc_profile = "/etc/profile"
    $etc_bash = "/etc/bash"
    $etc_bash_completion = "/etc/bash_completion.d"
    $etc_zprofile = "/etc/profile"
    $etc_zsh = "/etc/zsh"
    $not_bash = "BASH_ENV"
    $not_ksh = "KSH_VERSION"
    $not_shell = "OPTARG"
    $not_login = "login shell"
    $not_zshopts = "zshoptions"
    $not_zstyle = "zstyle"
    $not_source_etc_profile = "source /etc/profile"
    $not_dot_etc_profile = ". /etc/profile"
    $not_completion_bash = "completion bash"
    $not_autocompletion = "autocompletion"
    $not_autocomplete = "autocomplete"
  condition:
    any of ($etc*) and none of ($not*)
}
