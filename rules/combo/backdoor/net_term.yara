
rule readdir_openpty_socket : suspicious {
	meta:
		description = "Lists directories, opens pseudoterminals, resolves IPs"
	strings:
		$dlsym = "readdir" fullword
		$openpty = "openpty" fullword
		$system = "inet_addr" fullword
	condition:
		all of them in (1200..3000)
}

rule pseudoterminal_tunnel : suspicious {
	meta:
		description = "pseudoterminal and tunnel support"
	strings:
		$pty = "creack/pty" fullword
		$ptsname = "ptsname" fullword

		$t = /[\w]{0,16}tunnel[\w]{0,16}/ fullword
		$t2 = /[\w]{0,16}TUNNEL[\w]{0,16}/ fullword

		$not_qemu = "QEMU_IS_ALIGNED"
		// random wordlist, found in clickhouse and chezmoi
		$not_unbounded = "UNBOUNDED"
		// https://github.com/aws-samples/aws-iot-securetunneling-localproxy data
		$not_iot = "iotsecuredtunnel"
	condition:
		any of ($p*) and any of ($t*) and none of ($not*)
}

rule tty_shell : suspicious {
  meta:
    hash_2023_trojan_seaspy_barracuda = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"
  strings:
    $s_tty_shell = "tty shell" nocase
    $s_SSLshell = /SSL *Shell/ nocase
    $s_shellChannel = "ShellChannel"
    $not_login = "login_shell"
  condition:
    filesize < 26214400 and any of ($s*) and none of ($not*)
}

rule python_pty_spawner : suspicious {
  meta:
    ref1 = "https://juggernaut-sec.com/docker-breakout-lpe/"
    ref2 = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
  strings:
    $pty_spawn_bash = /pty.spawn\(\"\/bin\/[\w\" -\)]{,16}/
  condition:
    any of them
}


rule spectralblur_alike : suspicious {
	meta:
		description = "Uploads, provides a terminal, runs program"
	strings:
		$upload = "upload"
		$shell = "shell"
		$tcsetattr = "tcsetattr"
		$execve = "execve"
		$waitpid = "_waitpid"
		$unlink = "_unlink"
		$uname = "_uname"
	condition:
		all of them
}

rule miner_kvryr_stak_alike : suspicious {
	meta:
		description = "Uploads, provides a terminal, runs program"
	strings:
		$upload = "upload"
		$shell = "shell"
		$tcsetattr = "tcsetattr"
		$execve = "execve"
		$numa = "NUMA"
	condition:
		filesize < 64MB and all of them
}

rule proxy_http_aes_terminal_combo : notable {
  meta:
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2021_CoinMiner_TB_Camelot = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2021_ANDR_miner_eomap = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
  strings:
    $isatty = "isatty"
    $socks_proxy = "socks proxy"
    $socks = "SOCKS"
    $http = "http://"
    $http_req = "http request"
    $aes_gcm = "AESGCM"
    $aes_256 = "AES-256"
  condition:
    filesize < 26214400 and 85% of them
}

rule bpfdoor_alike : suspicious {
	meta:
		description = "Listens, provides a terminal, runs program"
	strings:
		$f_listen = "listen" fullword
		$f_grantpt =  "grantpt"  fullword
		$f_execve = "execve" fullword
		$f_ptmx = "/dev/ptmx"
		$not_sql_db = "sql.DB"
		$not_libc = "getusershell"
	condition:
		all of ($f*) and none of ($not*)
}

rule dlsym_openpty_system : suspicious {
	meta:
		description = "Resolves library, opens terminal, calls shell"
	strings:
		$dlsym = "dlsym" fullword
		$openpty = "openpty" fullword
		$system = "system"
	condition:
		all of them in (1200..3000)
}
