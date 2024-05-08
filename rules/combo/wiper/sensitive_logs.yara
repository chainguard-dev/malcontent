
rule system_log_references : high {
  meta:
    description = "sensitive Linux logs"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
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
    filesize < 67108864 and 3 of them
}
