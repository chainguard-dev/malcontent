
rule postgresql : notable {
  meta:
    description = "accesses PostgreSQL databases"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_Linux_Malware_Samples_efa8 = "efa875506296d77178884ba8ac68a8b6d6aef24e79025359cf5259669396e8dd"
    hash_2023_Linux_Malware_Samples_efac = "efacd163027d6db6009c7363eb2af62b588258789735352adcbc672cd412c7c1"
  strings:
    $ref = "postgresql" fullword
    $ref2 = "github.com/go-pg" fullword
  condition:
    any of them
}
