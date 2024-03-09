rule sleep_getuid_system_write {
  meta:
    hash_2021_CDDS_kAgent = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
    hash_hash_2015_trojan_Eleanor_conn = "5c16f53276cc4ef281e82febeda254d5a80cd2a0d5d2cd400a3e9f4fc06e28ad"
    hash_2021_Mettle = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2020_trojan_Meterpreter_Mettle_eukch = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
    hash_2020_trojan_Meterpreter_Metasploit_uzzxo = "444d8f5a716e89b5944f9d605e490c6845d4af369b024dd751111a6f13bca00d"
    hash_2023_Linux_Malware_Samples_4eae = "4eae9a20919d84e174430f6d33b4520832c9a05b4f111bb15c8443a18868c893"
    hash_2023_Linux_Malware_Samples_5c5b = "5c5b90cd6e56fdaa067ebf2423b44a83870808beba3ad7b2680022d05c6077b4"
    hash_2023_Linux_Malware_Samples_c058 = "c058aa5d69ce54c42ddd57bd212648fb62ef7325b371bf7198001e1f8bdf3c16"
  strings:
    $f_sleep = "_sleep"
    $f_getuid = "_getuid"
    $f_system = "_system"
    $f_fwrite = "_fwrite"
    $f_start = "start"
    $o_system = "_system"
    $o_seteuid = "_seteuid"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_ssh = "SSH2_MSG_NEWKEYS"
    $not_rsync = "RSYNC_PASSWORD"
    $not_unexpected = "unexpected command-line argument"
    $not_postfix = "/etc/postfix"
    $not_nss = "NSSUTIL"
    $not_unknown_flag = "unknown flag"
    $not_perl = "libperl"
    $not_isatty = "_isatty"
    $not_rustc = "/rustc/"
    $not_kandji = "com.kandji.profile.mdmprofile"
  condition:
    filesize < 10485760 and all of ($f*) and any of ($o_*) and none of ($not*)
}
