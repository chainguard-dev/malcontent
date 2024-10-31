
rule home_path : medium {
  meta:
    description = "references path within /home"
    hash_2024_SSH_Snake = "b0a2bf48e29c6dfac64f112ac1cb181d184093f582615e54d5fad4c9403408be"
    hash_2024_D3m0n1z3dShell_demonizedshell = "d7c34b9d711260c1cd001ca761f5df37cbe40b492f198b228916b6647b660119"
    hash_2024_locutus_dec = "86493d2b4f47ea277c2997aa723dcd6c99f75a829ac4d3b93e0b7870bfcc404c"
  strings:
    $home = /\/home\/[%\w\.\-\/]{0,64}/
    $not_build = "/home/build"
    $not_runner = "/home/runner"
  condition:
    $home and none of ($not*)
}
