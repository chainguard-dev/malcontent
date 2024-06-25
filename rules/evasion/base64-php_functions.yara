
rule base64_php_functions : high {
  meta:
    description = "References PHP functions in base64 form"
    hash_2023_0xShell_0xObs = "6391e05c8afc30de1e7980dda872547620754ce55c36da15d4aefae2648a36e5"
    hash_2023_0xShell_0xShellObs = "64771788a20856c7b2a29067f41be9cb7138c11a2cf2a8d17ab4afe73516f1ed"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
  strings:
    $Array = "Array" base64
    $array_push = "array_push" base64
    $count = "count" base64
    $empty = "empty" base64
    $explode = "explode" base64
    $foreach = "foreach" base64
    $getallheaders = "getallheaders" base64
    $gettype = "gettype" base64
    $inarray = "in_array" base64
    $is_dir = "is_dir" base64
    $is_writable = "is_writable" base64
    $isset = "isset" base64
    $move_uploaded_file = "move_uploaded_file" base64
    $scandir = "scandir" base64
    $str_pad = "str_pad" base64
    $strlen = "strlen" base64
    $strpos = "strpos" base64
    $assert = "assert" base64
    $create_function = "create_function" base64
    $curl_exec = "curl_exec" base64
    $curl_setopt = "curl_setopt" base64
    $current_user = "wp_get_current_user" base64
    $exec = "exec" base64
    $fclose = "fclose" base64
    $fgets = "fgets" base64
    $file_get_contents = "file_get_contents" base64
    $file_put_contents = "file_put_contents" base64
    $fopen = "fopen" base64
    $fputs = "fputs" base64
    $fread = "fread" base64
    $fsockopen = "fsockopen" base64
    $ftruncate = "ftruncate" base64
    $fwrite = "fwrite" base64
    $ini_set = "ini_set" base64
    $ob_start = "ob_start" base64
    $passthru = "passthru" base64
    $preg_replace = "preg_replace" base64
    $proc_open = "proc_open" base64
    $rawurldecode = "rawurldecode" base64
    $session_start = "session_start" base64
    $set_time_limit = "set_time_limit" base64
    $shell_exec = "shell_exec" base64
    $system = "system" base64
    $unlink = "unlink" base64
    $unserialize = "unserialize" base64
    $update_option = "update_option" base64
    $upload_dir = "wp_upload_dir" base64
    $wp_nonce_field = "wp_nonce_field" base64
    $wp_verify_nonce = "wp_verify_nonce" base64
  condition:
    any of them
}

rule base64_php_functions_multiple : critical {
  meta:
    description = "References multiple PHP functions in base64 form"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_0xencbase = "50057362c139184abb74a6c4ec10700477dcefc8530cf356607737539845ca54"
    hash_2023_0xShell_wesobase = "17a1219bf38d953ed22bbddd5aaf1811b9380ad0535089e6721d755a00bddbd0"
  strings:
    $Array = "Array" base64
    $array_push = "array_push" base64
    $count = "count" base64
    $empty = "empty" base64
    $explode = "explode" base64
    $foreach = "foreach" base64
    $getallheaders = "getallheaders" base64
    $gettype = "gettype" base64
    $inarray = "in_array" base64
    $is_dir = "is_dir" base64
    $is_writable = "is_writable" base64
    $isset = "isset" base64
    $move_uploaded_file = "move_uploaded_file" base64
    $scandir = "scandir" base64
    $str_pad = "str_pad" base64
    $strlen = "strlen" base64
    $strpos = "strpos" base64
    $assert = "assert" base64
    $create_function = "create_function" base64
    $curl_exec = "curl_exec" base64
    $curl_setopt = "curl_setopt" base64
    $current_user = "wp_get_current_user" base64
    $exec = "exec" base64
    $fclose = "fclose" base64
    $fgets = "fgets" base64
    $file_get_contents = "file_get_contents" base64
    $file_put_contents = "file_put_contents" base64
    $fopen = "fopen" base64
    $fputs = "fputs" base64
    $fread = "fread" base64
    $fsockopen = "fsockopen" base64
    $ftruncate = "ftruncate" base64
    $fwrite = "fwrite" base64
    $ini_set = "ini_set" base64
    $ob_start = "ob_start" base64
    $passthru = "passthru" base64
    $preg_replace = "preg_replace" base64
    $proc_open = "proc_open" base64
    $rawurldecode = "rawurldecode" base64
    $session_start = "session_start" base64
    $set_time_limit = "set_time_limit" base64
    $shell_exec = "shell_exec" base64
    $system = "system" base64
    $unlink = "unlink" base64
    $unserialize = "unserialize" base64
    $update_option = "update_option" base64
    $upload_dir = "wp_upload_dir" base64
    $wp_nonce_field = "wp_nonce_field" base64
    $wp_verify_nonce = "wp_verify_nonce" base64
  condition:
    2 of them
}
