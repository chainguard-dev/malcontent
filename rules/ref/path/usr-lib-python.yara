
rule usr_lib_python_path_val : notable {
  meta:
    description = "References paths within /usr/lib/python"
    hash_2024_2024_PAN_OS_Upstyle_update = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
    hash_2024_2024_PAN_OS_Upstyle_update_base64_payload1 = "e96f6ca8ecc00fcfac88679e475022091ce47f75c54f47570d66a56d77cd5ea6"
  strings:
    $ref = /\/usr\/lib\/python[\w\-\.\/]{0,128}/
  condition:
    $ref
}
