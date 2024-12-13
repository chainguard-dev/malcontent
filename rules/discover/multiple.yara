rule sys_net_recon: medium {
  meta:
    description = "collects system and network information"

  strings:
    $net_ipconfig          = "ipconfig" fullword
    $net_ipaddr            = "ipaddr" fullword
    $sys_getpass           = "getpass.getuser"
    $sys_whoami            = "whoami" fullword
    $sys_platform_node     = "platform.node()" fullword
    $sys_platform_platform = "platform.platform()" fullword
    $sys_platform_system   = "platform.system()" fullword
    $sys_tasklist          = /tasklist.{0,4}\/svc/ fullword
    $net_ifconfig          = "ifconfig" fullword
    $net_ip_addr           = /ip.{0,4}addr/ fullword
    $net_ip_route          = /ip.{0,4}route/
    $net_netstat           = /netstat.{0,4}-a/
    $net_ufw               = /ufw.{0,4}status/
    $sys_hostname          = "hostname" fullword
    $sys_id                = "id" fullword
    $sys_lspi              = "lspci"
    $sys_sudo              = /sudo.{0,4}-l/
    $sys_uname_a           = "uname -a"
    $sys_uname_r           = "uname -r"
    $sys_macos             = "isPlatformOrVariant"
    $sys_systeminfo        = "systeminfo" fullword

  condition:
    filesize < 512KB and any of ($sys*) and any of ($net*)
}

rule user_sys_net_disk_recon: high {
  meta:
    description = "collects user, system, disk, and network information"

  strings:
    $net_ipconfig          = "ipconfig"
    $net_ipaddr            = "ipaddr" fullword
    $user_getpass          = "getpass.getuser"
    $user_whoami           = "whoami"
    $sys_platform_node     = "platform.node()" fullword
    $sys_platform_platform = "platform.platform()" fullword
    $sys_platform_system   = "platform.system()" fullword
    $sys_tasklist          = /tasklist.{0,4}\/svc/ fullword
    $net_ifconfig          = "ifconfig" fullword
    $net_ip_addr           = /ip.{0,4}addr/ fullword
    $net_ip_route          = /ip.{0,4}route/
    $net_netstat           = /netstat.{0,4}-[arn]/
    $net_ufw               = /ufw.{0,4}status/
    $sys_hostname          = "hostname" fullword
    $sys_id                = "id" fullword
    $sys_lspi              = "lspci"
    $sys_sudo              = /sudo.{0,4}-l/
    $sys_uname_a           = "uname -a"
    $sys_uname_r           = "uname -r"
    $sys_macos             = "isPlatformOrVariant"
    $sys_systeminfo        = "systeminfo" fullword
    $disk_df_h             = "df -h"
    $disk_space            = "Disk space"

  condition:
    filesize < 512KB and any of ($sys*) and any of ($net*) and any of ($user*) and any of ($disk*)
}

private rule discover_obfuscate {
  strings:
    $b64decode = "b64decode"
    $base64    = "base64"
    $codecs    = "codecs.decode"
    $x_decode  = /\w{0,16}XorDecode[\w]{0,32}/
    $x_encode  = /\w{0,16}XorEncode[\w]{0,32}/
    $x_file    = /\w{0,16}XorFile[\w]{0,32}/
    $x_decode_ = /\w{0,16}xor_decode[\w]{0,32}/
    $x_encode_ = /\w{0,16}xor_encode[\w]{0,32}/
    $x_file_   = /\w{0,16}xor_file[\w]{0,32}/

  condition:
    filesize < 512KB and any of them
}

private rule discover_exfil {
  strings:
    $f_app_json = "application/json"
    $f_post     = "requests.post"
    $f_nsurl    = "NSURLRequest"
    $f_curl     = /curl.{0,32}-X POST/

    $not_requests_utils = "requests.utils"

  condition:
    filesize < 512KB and any of ($f*) and none of ($not*)
}

rule sys_net_recon_exfil: high {
  meta:
    description = "may exfiltrate collected system and network information"

  strings:
    $not_curl      = "CURLAUTH_ONLY"
    $not_cloudinit = "cloudinit" fullword

  condition:
    sys_net_recon and discover_obfuscate and discover_exfil and none of ($not*)
}
