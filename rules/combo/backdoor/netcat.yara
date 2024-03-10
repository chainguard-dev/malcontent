rule netcat_exec_backdoor : suspicious {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    hash_2023_uacert_nc = "dd8a8a9dde32a14a7222a28e878d13c4f0bccd5eb54d0575fa6332d001226715"
  strings:
    $nc_e = "nc -e "
  condition:
    filesize < 10485760 and all of them
}
