rule crontab_writer : suspicious {
  meta:
	description = "May use crontab to persist"
    hash_2020_FinSpy_helper2 = "af4ad3b8bf81a877a47ded430ac27fdcb3ddd33d3ace52395f76cbdde46dbfe0"
    hash_2022_XorDDoS_0Xorddos = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2013_Resources_installer = "5dce86eb6881f8088660b961746623b81d38f8bccb6693116296748fbe1f3719"
    hash_2021_trojan_Gafgyt_fszhv = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2021_trojan_Gafgyt_malxmr = "1b5bd0d4989c245af027f6bc0c331417f81a87fff757e19cdbdfe25340be01a6"
    hash_2020_Prometei_B_uselvh323 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"
    hash_2020_Prometei_lbjon = "75ea0d099494b0397697d5245ea6f2b5bf8f22bb3c3e6d6d81e736ac0dac9fbc"
    hash_2023_Linux_Malware_Samples_aab5 = "aab526b32d703fd9273635393011a05c9c3f6204854367eb0eb80894bbcfdd42"
  strings:
    $c_etc_crontab = /\/etc\/cron[\/\w\.]{0,32}/
    $c_crontab_e = "crontab -"
    $c_var_spool_cron = "/var/spool/cron"
    $c_root_cron_entry = "* * * * root"
    $c_reboot = "@reboot"
    $c_daily = "@daily"
    $not_usage = "usage: cron"
  condition:
    filesize < 2097152 and any of ($c*) and none of ($not*)
}


rule crontab_danger_path : suspicious {
  meta:
    ref = "https://blog.xlab.qianxin.com/mirai-nomi-en/"
	description = "Starts from a dangerous-looking path"
  strings:
    $any_val = /\* \* \* \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
    $reboot_val = /@reboot \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
  condition:
    filesize < 100MB and any of them
}
