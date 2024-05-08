
rule hacktool_nmap : notable {
  strings:
    $nmap_payload = "nmap-payload"
  condition:
    any of them
}
