
rule macaddr : medium {
  meta:
    description = "Retrieves network MAC address"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"
    hash_2023_Downloads_b56a = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2024_Downloads_fd0b = "fd0b5348bbfd013359f9651268ee67a265bce4e3a1cacf61956e3246bac482e8"
  strings:
    $ref = "MAC address"
    $ref2 = "get_if_mac_addr"
    $ref3 = "macAddress" fullword
  condition:
    any of them
}
