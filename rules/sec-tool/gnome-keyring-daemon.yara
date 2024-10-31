
rule gnome_keyring_daemon : medium {
  meta:
    hash_2024_dumpcreds_mimipenguin = "de769bcc751c3c237be457dbf645d23bb2b9d2afb38b19fbe79934ceaec5e5aa"
    hash_2024_dumpcreds_mimipenguin = "79b478d9453cb18d2baf4387b65dc01b6a4f66a620fa6348fa8dbb8549a04a20"
    hash_2024_dumpcreds_mimipenguin = "3acfe74cd2567e9cc60cb09bc4d0497b81161075510dd75ef8363f72c49e1789"
  strings:
    $ref = "gnome-keyring-da"
  condition:
    $ref
}
