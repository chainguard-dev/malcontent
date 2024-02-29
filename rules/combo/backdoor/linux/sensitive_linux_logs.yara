
rule system_log_references {
  meta:
	description = "Accesses multiple sensitive Linux logs"
  strings:
    $wtmp = "/var/log/wtmp"
    $secure = "/var/log/secure"
    $cron = "/var/log/cron"
    $iptables = "/var/log/iptables.log"
    $auth = "/var/log/auth.log"
    $cron_log = "/var/log/cron.log"
    $httpd = "/var/log/httpd"
    $syslog = "/var/log/syslog"
    $btmp = "/var/log/btmp"
    $lastlog = "/var/log/lastlog"
	$run_log = "/run/log/"
  condition:
    2 of them
}