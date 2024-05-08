
rule node_hex_parse : suspicious {
  meta:
    description = "converts hex data to ASCII"
    hash_2023_package_bgService = "36831e715a152658bab9efbd4c2c75be50ee501b3dffdb5798d846a2259154a2"
    hash_2023_getcookies_harness = "99b1563adea48f05ff6dfffa17f320f12f0d0026c6b94769537a1b0b1d286c13"
  strings:
    $ref = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
  condition:
    $ref
}
