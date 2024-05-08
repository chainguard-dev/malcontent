
rule basic_recon : notable {
  strings:
    $c_whoami = "whoami" fullword
    $c_id = "id" fullword
    $c_hostname = "hostname" fullword
    $c_uname = "uname -a"
    $c_ip_addr = "ip addr" fullword
    $not_usage = "Usage: inet"
    $not_apple_smb = "com.apple.smbd"
    $not_bashopts = "BASHOPTS"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_license = "For license information please see"
  condition:
    filesize < 26214400 and 3 of ($c*) and none of ($not*)
}

rule invasive_recon_val : notable {
  strings:
    $c_ifconfig = /ifconfig.{0,4}-a/ fullword
    $c_lspi = "lspci"
    $c_ufw = /ufw.{0,4}status/
    $c_sudo = /sudo.{0,4}-l/
    $c_ip_route = /ip.{0,4}route/
    $c_netstat = /netstat.{0,4}-a/
    $c_ip_addr = /ip.{0,4}addr/ fullword
    $not_usage = "Usage: inet"
    $not_apple_smb = "com.apple.smbd"
    $not_bashopts = "BASHOPTS"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_license = "For license information please see"
  condition:
    filesize < 26214400 and any of ($c*) and none of ($not*)
}
