
rule esxcli_caller : suspicious {
  meta:
    hash_2023_BlackCat_45b8 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2023_Multios_Ransomware_DarkSide_da3b = "da3bb9669fb983ad8d2ffc01aab9d56198bd9cedf2cc4387f19f4604a070a9b5"
  strings:
    $esxcli = "esxcli"
  condition:
    any of them
}
