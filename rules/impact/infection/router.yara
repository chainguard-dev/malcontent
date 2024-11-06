rule router_malware_paths: critical {
  meta:
    description              = "access paths seen in router malware"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_Downloads_abf0 = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_c91c = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"

  strings:
    $f_bin_busybox   = "/bin/busybox"
    $f_usr_sbin      = "/usr/sbin"
    $f_admin_console = "/var/www/cgi-bin/admin_console_core.cgi"
    $f_telnetd       = "telnetd"
    $f_httpd         = "/usr/bin/httpd"
    $f_upnp          = "/dev/upnp"
    $f_ipcam_app     = "/usr/share/ipcam/app"
    $f_ping_test     = "/opt/www/cgi-bin/ping_test.cgi"
    $f_usr_bin_ps    = "/usr/bin/ps"
    $f_wget          = "/wget"
    $f_curl          = "/curl"
    $not_dos2unix    = "/usr/bin/dos2unix"
    $not_setfont     = "/usr/sbin/setfont"

  condition:
    5 of ($f*) and none of ($not*)
}

rule c_router_malware: high {
  meta:
    description              = "possible mirai-like router malware"
    hash_2023_Downloads_98e7 = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_Downloads_abf0 = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_Downloads_c91c = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"

  strings:
    $f_bin_busybox = "/bin/busybox"
    $maps          = "/proc/self/maps"
    $memory        = "/proc/sys/vm/overcommit_memory"
    $cpu           = "/sys/devices/system/cpu"
    $null          = "/dev/null"
    $profile       = "/var/profile"
    $exe           = "/proc/self/exe"
    $ngroups       = "/proc/sys/kernel/ngroups_max"

  condition:
    filesize < 1MB and all of them
}

rule go_router_malware: high linux {
  meta:
    description = "possible Kaiji-like router malware"

  strings:
    $fastrand   = "valyala/fastrand"
    $gopsutil   = "shirou/gopsutil"
    $os_exec    = "os/exec"
    $makePacket = "makePacket" fullword
    $cbc        = "NewCBCDecrypter"

  condition:
    filesize < 3MB and all of them
}
