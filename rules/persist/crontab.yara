rule crontab_writer : medium {
  meta:
    description = "May use crontab to persist"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
    hash_2023_ZIP_server = "b69738c655dee0071b1ce37ab5227018ebce01ba5e90d28bd82d63c46e9e63a4"
  strings:
    $c_etc_crontab = /\/etc\/cron[\/\w\.]{0,32}/
    $c_crontab_e = "crontab -"
    $c_var_spool_cron = "/var/spool/cron"
    $not_usage = "usage: cron"
  condition:
    filesize < 50MB and any of ($c*) and none of ($not*)
}

rule crontab_entry : high {
  meta:
    description = "Uses crontab to persist"
  strings:
		$crontab = "crontab"
		$repeat_every_minutes = /\*\/\d \* \* \* \*/
		$repeat_every_minute = "* * * * *"
		$repeat_hourly = /\d \* \* \* \*/
		$repeat_root = "* * * * root"
		$repeat_daily = "@daily"
  condition:
		filesize < 50MB and $crontab and any of ($repeat*)
}

rule crontab_danger_path : high {
  meta:
    ref = "https://blog.xlab.qianxin.com/mirai-nomi-en/"
    description = "Starts from a dangerous-looking path"
    hash_2023_Linux_Malware_Samples_741a = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2023_Linux_Malware_Samples_ee0e = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
  strings:
    $any_val = /\* \* \* \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
    $reboot_val = /@reboot \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
  condition:
    filesize < 104857600 and any of them
}
