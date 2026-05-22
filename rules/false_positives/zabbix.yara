rule zabbix_binary: override {
  meta:
    description    = "Zabbix monitoring system - agent, server, proxy, get, sender"
    curl_easy      = "low"
    proc_s_cmdline = "low"
    proc_d_cmdline = "low"

  strings:
    $vendor   = "Zabbix SIA"
    $homepage = "Zabbix home page: <https://www.zabbix.com>"

  condition:
    filesize < 10MB and all of them
}
