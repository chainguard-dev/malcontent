private rule sensitive_log_files {
  strings:
    $wtmp     = "/var/log/wtmp"
    $secure   = "/var/log/secure"
    $cron     = "/var/log/cron"
    $iptables = "/var/log/iptables.log"
    $auth     = "/var/log/auth.log"
    $cron_log = "/var/log/cron.log"
    $httpd    = "/var/log/httpd"
    $syslog   = "/var/log/syslog"
    $btmp     = "/var/log/btmp"
    $lastlog  = "/var/log/lastlog"
    $run_log  = "/run/log/"
    $mail_log = "/var/spool/mail/root"

  condition:
    filesize < 16KB and 2 of them
}

rule echo_log_wiper: critical {
  meta:
    description = "overwrites critical system logs"

  strings:
    $var_spool = /echo.{0,4}\> {0,2}\/var\/spool\/mail\/root/
    $var_log   = /echo.{0,4}\> {0,2}\/var\/log\/\w{0,8}/

  condition:
    filesize < 16KB and sensitive_log_files and any of them
}

rule log_remover: critical {
  meta:
    description = "overwrites critical system logs"

  strings:
    $var_spool = /rm {1,2}-{0,4}\/var\/spool\/mail\/root/
    $var_log   = /rm {1,2}-{0,4}\/var\/log\/\w{0,8}/

  condition:
    filesize < 16KB and sensitive_log_files and any of them
}
