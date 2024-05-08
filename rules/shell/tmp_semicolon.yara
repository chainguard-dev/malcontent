
rule semicolon_short_tmp : suspicious {
  meta:
    description = "unusual one-liners involving /tmp"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
    hash_2023_Unix_Dropper_Mirai_0e91 = "0e91c06bb84630aba38e9c575576b46240aba40f36e6142c713c9d63a11ab4bb"
    hash_2023_Unix_Dropper_Mirai_4d50 = "4d50bee796cda760b949bb8918881b517f4af932406307014eaf77d8a9a342d0"
  strings:
    $tmp_before = /[\w\/ \-\;]{0,32} \/tmp\/[a-z]{1,5} {0,2};/
    $var_tmp_before = /[\w\/ \-\;]{0,32} \/var\/tmp\/[a-z]{1,5} {0,2};/
    $tmp_after = /[\w\/ \-]{0,32}; {0,2}\/tmp\/[a-z]{1,5}[\w\/ \-\&\;]{0,32}/
    $var_tmp_after = /[\w\/ \-]{0,32}; {0,2}\/var\/tmp\/[a-z]{1,5}[\w\/ \-\&\;]{0,32}/
  condition:
    any of them
}
