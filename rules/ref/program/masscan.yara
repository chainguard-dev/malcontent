
rule masscan : notable {
  strings:
    $ref = "masscan" fullword
  condition:
    $ref
}

rule masscan_config {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
  strings:
    $adapter_ip = "adapter-ip"
    $nocapture = "nocapture"
    $output_format = "output-format"
    $randomize_hosts = "randomize-hosts"
  condition:
    75% of them
}
