rule var_root_path : high macos {
  meta:
    description = "path reference within /var/root"
    hash_2022_Gimmick_CorelDRAW = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
    hash_2018_OSX_Dummy_script = "ced05b1f429ade707691b04f59d7929961661963311b768d438317f4d3d82953"
  strings:
    $ref = /\/var\/root\/[\%\w\.\-\/]{4,32}/ fullword
  condition:
    $ref
}
