
rule eval : medium {
  meta:
    description = "evaluate code dynamically using eval()"
    hash_2023_0xShell_f = "9ce3da0322ee42e9119abb140b829efc3c94ea802df7a6f3968829645e1a5330"
    hash_2023_0xShell_lndex = "9b073472cac7f3f8274165a575e96cfb4f4eb38471f6a8e57bb9789f3f307495"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
    $val = /eval\([a-z\"\'\(\,\)]{1,32}/ fullword
    $not_empty = "eval()"
  condition:
    $val and none of ($not*)
}

rule python_exec : medium {
  meta:
    description = "evaluate code dynamically using exec()"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_misc_mr_robot = "630bbcf0643d9fc9840f2f54ea4ae1ea34dc94b91ee011779c8e8c91f733c9f5"
  strings:
    $val = /exec\([a-z\"\'\(\,\)]{1,32}/ fullword
    $empty = "exec()"
  condition:
    $val and not $empty
}

rule shell_eval : medium {
  meta:
    description = "evaluate shell code dynamically using eval"
    hash_1980_FruitFly_A_205f = "205f5052dc900fc4010392a96574aed5638acf51b7ec792033998e4043efdf6c"
    hash_1980_FruitFly_A_ce07 = "ce07d208a2d89b4e0134f5282d9df580960d5c81412965a6d1a0786b27e7f044"
    hash_2023_init_d_netconsole = "ce60bd5b98735dc901a8ca8080fb7137a068de5cb0b75561c04ab4cb3bad3dbe"
  strings:
    $val = /eval \$\w{0,64}/ fullword
    $not_fish_completion = "fish completion"
  condition:
    $val and none of ($not*)
}

rule php_create_function_no_args : high {
  meta:
    description = "dynamically creates PHP functions without arguments"
    hash_2024_Obfuscated_Webshell_75f2c462f011da26a97e28fcb3afb4740826f960 = "a3f1518a22d47a5b24280171a050b774b3ec0822702f7e6b2ec70a0b97a55927"
  strings:
    $val = /create_function\([\'\"]{2},\$/
  condition:
    any of them
}

rule php_at_eval : critical {
  meta:
    description = "evaluates code in a way that suppresses errors"
    hash_2017_mybiubiubiu_0_1_0_setup = "a8a4a9a8eed6498e1f3c35282b50074fd57c7802058aac4895346d684a6881a3"
    hash_2017_tests = "f1a947148c092a58e354e46082b0187bce0eea38fab2a7638eb268da0752657b"
    hash_2017_mybiubiubiu_0_1_1_setup = "afd6712c7c190465c459ab1049cd559e4a2f00a5e1a4e1fe063cfefc19a330ef"
  strings:
    $at_eval = /@eval\s{0,8}\(.{0,32}/
  condition:
    any of them
}
