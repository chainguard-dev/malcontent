rule app_data: medium windows {
  meta:
    description = "references Windows user application data"

  strings:
    $user  = /Default User.{0,32}Application Data/
    $local = /LocalService.{0,32}Application Data/
    $net   = /NetworkService.{0,32}Application Data/

  condition:
    any of them
}
