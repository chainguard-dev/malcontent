rule go_pty_daemonize_net : critical {
	meta:
		description = "daemonizes and exposes a terminal to the internet"
	strings:
		$d1 = "go-daemon" fullword
		$d2 = "xdaemon" fullword

		$pty = "creack/pty" fullword
		$ptsname = "ptsname" fullword

		$net = "net.socket" fullword
		$nsocks = "go-socks5"
	condition:
		any of ($d*) and any of ($p*) and any of ($n*)
}
