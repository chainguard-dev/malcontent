rule setenv_putenv: harmless {
  meta:
    description = "places a variable into the environment"

  strings:
    $setenv = "setenv" fullword
    $putenv = "putenv" fullword
    $set    = /SetEnvironmentVariable\w{0,4}/

  condition:
    any of them
}
