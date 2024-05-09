
rule sysinfo_http : high {
  meta:
    description = "sends host information via HTTP GET variables"
    hash_2023_Unix_Trojan_Redxor_0a76 = "0a76c55fa88d4c134012a5136c09fb938b4be88a382f88bf2804043253b0559f"
  strings:
    $ref = "&hostname="
    $ref2 = "&uname="
  condition:
    any of them
}
