rule masscan: medium {
  meta:
    description = "references 'masscan', an asynchronous TCP port scanner"

  strings:
    $ref        = "masscan" fullword
    $not_kibana = "ua0-600-60x" fullword

  condition:
    $ref and none of ($not*)
}

rule masscan_elf: high linux {
  meta:
    description = "executes 'masscan', an asynchronous TCP port scanner"

  strings:
    $ref        = "masscan" fullword
    $run_exec   = "execve" fullword
    $run_system = "system" fullword
    $run_go     = "exec.(*Cmd).Run"
    $not_nmap   = "nmap" fullword

  condition:
    filesize < 10MB and uint32(0) == 1179403647 and $ref and any of ($run*) and none of ($not*)
}

rule masscan_config {
  meta:
    ref = "https://cert.gov.ua/article/6123309"

  strings:
    $adapter_ip      = "adapter-ip"
    $nocapture       = "nocapture"
    $output_format   = "output-format"
    $randomize_hosts = "randomize-hosts"

  condition:
    75 % of them
}
