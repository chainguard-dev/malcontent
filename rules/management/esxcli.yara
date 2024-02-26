
rule esxcli_caller : suspicious {
  meta:
    hash_2023_RedAlert_redniev = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
    hash_2023_Royal = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_blackcat_x64 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2023_HelloKitty_A = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
    hash_2023_Sodinokibi = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
    hash_2023_Multios_Ransomware_DarkSide_da3b = "da3bb9669fb983ad8d2ffc01aab9d56198bd9cedf2cc4387f19f4604a070a9b5"
  strings:
    $esxcli = "esxcli"
  condition:
    any of them
}
