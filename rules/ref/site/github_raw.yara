
rule github_raw_usercontent : notable {
  meta:
    description = "References raw.githubusercontent.com"
  strings:
    $raw_github = "raw.githubusercontent.com"
    $not_node = "NODE_DEBUG_NATIVE"
  condition:
    $raw_github and $not_node
}

rule github_raw_user : notable {
  meta:
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
  strings:
    $github = "github.com"
    $raw_master = "raw/master"
    $raw_main = "raw/main"
    $not_node = "NODE_DEBUG_NATIVE"
  condition:
    $github and any of ($raw*) and none of ($not*)
}
