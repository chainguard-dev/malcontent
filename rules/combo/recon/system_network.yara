
rule sys_net_recon : medium {
  meta:
    description = "collects system and network information"
    hash_2023_Downloads_f864 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2023_Linux_Malware_Samples_3292 = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
  strings:
	$net_ipconfig = /ipconfig.{0,4}\/all/ fullword
	$sys_getpass = "getpass.getuser"
	$sys_platform_node = "platform.node()" fullword
	$sys_platform_platform = "platform.platform()" fullword
	$sys_platform_system = "platform.system()" fullword
	$sys_tasklist = /tasklist.{0,4}\/svc/ fullword
    $net_ifconfig = /ifconfig.{0,4}-a/ fullword
    $net_ip_addr = /ip.{0,4}addr/ fullword
    $net_ip_route = /ip.{0,4}route/
    $net_netstat = /netstat.{0,4}-a/
    $net_ufw = /ufw.{0,4}status/
    $sys_hostname = "hostname" fullword
    $sys_id = "id" fullword
    $sys_lspi = "lspci"
    $sys_sudo = /sudo.{0,4}-l/
    $sys_uname = "uname -a"
    $sys_whoami = "whoami" fullword
  condition:
    filesize < 128KB and 2 of ($sys*) and any of ($net*)
}

private rule obfuscate {
	strings:
		$b64decode = "b64decode"
		$base64 = "base64"
		$codecs = "codecs.decode"
	condition:
		filesize < 32KB and any of them
}


private rule exfil {
	strings:
		$f_b64decode = "application/json"
		$f_base64 = "base64"
		$f_codecs = "codecs.decode"
		$f_post = "requests.post"
	condition:
		filesize < 32KB and any of them
}


rule sys_net_recon_exfil : high {
  meta:
    description = "may exfiltrate collected system and network information"
   condition:
     sys_net_recon and (obfuscate or exfil)
}