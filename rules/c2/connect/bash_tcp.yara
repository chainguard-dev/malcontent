
rule bash_tcp : high {
  meta:
    description = "sends data via /dev/tcp (bash)"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
  strings:
    $ref = /[\w \-\<]{0,32}>"{0,1}\/dev\/tcp\/[\$\{\/\:\-\w\"]{0,32}/
  condition:
    $ref
}
