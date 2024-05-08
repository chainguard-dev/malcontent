
rule crontab_writer : suspicious {
  meta:
    description = "May use crontab to persist"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
    hash_2023_ZIP_server = "b69738c655dee0071b1ce37ab5227018ebce01ba5e90d28bd82d63c46e9e63a4"
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
    filesize < 104857600 and any of them
}
