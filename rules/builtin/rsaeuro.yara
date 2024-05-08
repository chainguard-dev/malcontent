
rule rsaeuro_user : notable {
  meta:
    hash_2017_Dockster = "8da09fec9262d8bbeb07c4e403d1da88c04393c8fc5db408e1a3a3d86dddc552"
  strings:
    $toolkit = "RSAEURO Toolkit"
  condition:
    any of them
}
