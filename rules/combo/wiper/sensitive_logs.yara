
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
	$mail_log = "/var/spool/mail/root"
  condition:
    filesize < 67108864 and uint32(0) == 1179403647 and 3 of them
}

rule echo_log_wiper : critical {
	meta:
		description = "overwrites critical system logs"
	strings:
		$var_spool = /echo.{0,4}\> {0,2}\/var\/spool\/mail\/root/
		$var_log = /echo.{0,4}\> {0,2}\/var\/log\/\w{0,8}/
	condition:
		filesize < 16KB and system_log_references and any of them
}

rule log_remover : critical {
	meta:
		description = "overwrites critical system logs"
	strings:
		$var_spool = /rm {1,2}-{0,4}\/var\/spool\/mail\/root/
		$var_log = /rm {1,2}-{0,4}\/var\/log\/\w{0,8}/
	condition:
		filesize < 16KB and system_log_references and any of them
}