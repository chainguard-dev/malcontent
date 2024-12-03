rule router_malware_paths: high {
  meta:
    description = "access paths seen in router malware"

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
    description = "possible mirai-like router malware"

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
