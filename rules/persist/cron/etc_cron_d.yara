rule cron_d_user: high {
  meta:
    description = "Uses /etc/cron.d to persist"

  strings:
    $c_etc_crontab = /\/etc\/cron\.d\/[\w\.\-\%\/]{1,16}/

    $not_usage = "usage: cron"

  condition:
    filesize < 52428800 and any of ($c*) and none of ($not*)
}
