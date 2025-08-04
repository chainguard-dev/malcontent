rule crontab_support: medium {
  meta:
    description = "supports crontab manipulation"

  strings:
    $crontab = "crontab" fullword

  condition:
    any of them
}

rule crontab_list: medium {
  meta:
    description = "lists crontab entries, may also persist"

  strings:
    $crontab = "crontab" fullword

  condition:
    any of them
}

rule crontab_writer: medium {
  meta:
    description = "May use crontab to persist"

  strings:
    $c_crontab_e      = "crontab -"
    $c_var_spool_cron = "/var/spool/cron"
    $not_usage        = "usage: cron"

  condition:
    filesize < 52428800 and any of ($c*) and none of ($not*)
}

rule crontab_entry: high {
  meta:
    description = "Uses crontab to persist"

  strings:
    $crontab              = "crontab"
    $repeat_every_minutes = /\*\/\d \* \* \* \*/
    $repeat_every_minute  = "* * * * *"
    $repeat_hourly        = /\d \* \* \* \*/
    $repeat_root          = "* * * * root"
    $repeat_daily         = "@daily"

    $not_cron_date    = "CronDate"
    $not_minute       = "Minute"
    $not_minutes      = "minutes"
    $not_days         = "Days in month"
    $not_day_of_week  = "dayOfWeek"
    $not_day_of_month = "dayOfMonth"

    $not_wolfi1 = "# As wolfi-baselayout does provide /var/spool/cron already, and we can not create this"
    $not_wolfi2 = "# directory in the package, we need to create the cron file in the post-install scriptlet."
    $not_wolfi3 = "# Since scriptlets don't run in apko, this is for the `apk add` command only."

  condition:
    filesize < 6KB and $crontab and any of ($repeat*) and none of ($not*)
}

rule crontab_danger_path: high {
  meta:
    ref         = "https://blog.xlab.qianxin.com/mirai-nomi-en/"
    description = "Starts from a dangerous-looking path"

  strings:
    $any_val    = /\* \* \* \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
    $reboot_val = /@reboot \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/

  condition:
    filesize < 104857600 and any of them
}

rule hidden_crontab: critical {
  meta:
    description = "persists via a hidden crontab entry"

  strings:
    $crontab              = "crontab"
    $c_periodic_with_user = /\*[\/\d]{0,3} \* \* \* \* [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_periodic           = /\*[\/\d]{0,3} \* \* \* \* [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_nickname_with_user = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_nickname           = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/

  condition:
    $crontab and any of ($c_*)
}

rule echo_crontab: high {
  meta:
    description = "persists via crontab entry (echo)"

  strings:
    $echo = /echo.{0,10}\* \* \* \*.{0,24}cron[\w\/ \-]{0,16}/

  condition:
    $echo
}

rule c_string_crontab: high {
  meta:
    description = "persists via crontab entry (C formatted string)"

  strings:
    $c_string = /\*[\/0-9]{0,3}\s{1,4}\*\s{1,4}\*\s{1,4}\*\s{1,4}\*\s.{0,4}\%s[\"\w\-]{0,8}/
    $crontab  = "crontab"

  condition:
    all of them
}
