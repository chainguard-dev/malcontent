rule bash_tcp: high {
  meta:
    description = "sends data via /dev/tcp (bash)"

    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"

  strings:
    $ref = /[\w \-\<]{0,32}>"{0,1}\/dev\/tcp\/[\$\{\/\:\-\w\"]{0,32}/

  condition:
    $ref
}
