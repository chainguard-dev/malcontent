
rule bash_dev_tcp : high exfil {
  meta:
    description = "uses /dev/tcp for network access (bash)"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
  strings:
    $ref = "/dev/tcp"
    $posixly_correct = "POSIXLY_CORRECT"
    $not_comment = "# Check that both our processes are running on their tcp port"
    $not_get = /GET \/ HTTP\/1.1\n{1,2} >/
    $not_localhost_8080 = "/dev/tcp/127.0.0.1/8080"
  condition:
    $ref and not $posixly_correct and none of ($not*)
}


rule bash_dev_tcp_hardcoded_ip : critical {
  meta:
    description = "hardcoded /dev/tcp host:port"
  strings:
    $dev_tcp = /\/dev\/tcp\/[\w\.]{8,16}\/\d{1,6}/
    $not_comment = "# Check that both our processes are running on their tcp port"
    $not_get = /GET \/ HTTP\/1.1\n{1,2} >/
    $not_localhost_8080 = "/dev/tcp/127.0.0.1/8080"
  condition:
	  filesize < 1KB and $dev_tcp and none of ($not*)
}
