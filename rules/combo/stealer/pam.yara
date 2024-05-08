
rule pam_passwords : suspicious {
  meta:
    description = "password authentication module may record passwords"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Symbiote_1211 = "121157e0fcb728eb8a23b55457e89d45d76aa3b7d01d3d49105890a00662c924"
  strings:
    $auth = "pam_authenticate"
    $pass = "password"
    $f_open = "open"
    $f_fopen = "fopen"
    $f_socket = "socket"
    $f_exfil = "exfil"
  condition:
    $auth and $pass and any of ($f*)
}
