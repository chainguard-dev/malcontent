
rule user_agent_netinfo: suspicious {
	meta:
		description = "Has a user agent and collects network info"
	strings:
		$ua = "User-Agent"
		$ua_moz = "Mozilla/"
		$ua_msie = "compatible; MSIE"
		$n_ifconfig = "ifconfig"
		$n_route = "/proc/net/route"
	condition:
		any of ($ua*) and any of ($n*)
}
