
rule py_lib_alias_val : notable {
  meta:
    description = "aliases core python library to an alternate name"
    hash_2022_requests_init = "4b62b48e754fe824ab4f9d5272d172881d177c8f07f4db7b12acc44400f8e208"
    hash_2022_requests_compat = "cb19ed54e4841c632b9fb14daffdf61046a6d5934074f45d484d77ff2687cd39"
    hash_2022_tests_compat = "d58ff5e3167de0140a667cc51427f809c552e485875c95b9dad43ce13ba15083"
  strings:
    $val = /from \w{2,16} import \w{2,16} as \w{1,32}/ fullword
  condition:
    $val
}
