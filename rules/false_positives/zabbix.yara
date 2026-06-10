rule zabbix_binary: override {
  meta:
    description     = "Zabbix monitoring system - agent, server, proxy, get, sender"
    curl_easy       = "low"
    curl_easy_exfil = "low"
    proc_s_cmdline  = "low"
    proc_d_cmdline  = "low"

  strings:
    $vendor   = "Zabbix SIA"
    $homepage = "Zabbix home page: <http"

  condition:
    filesize < 10MB and all of them
}
