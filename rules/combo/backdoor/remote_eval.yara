import "math"

rule remote_eval : critical {
  meta:
    description = "Evaluates remotely sourced code"
    hash_2019_restclient_request = "ba46608e52a24b7583774ba259cf997c6f654a398686028aad56855a2b9d6757"
    hash_2024_analyze_me_1_0_0_setup = "ca9c74630ed814053220129ee6c43668e66898983d9be5e34b406bbd3ad95b1e"
  strings:
    $http = "http"
    $eval_open_ruby = /eval\(open[\(\)\"\'\-\w:\/\.]{0,64}/
    $exec_requests = /exec\(requests\.get[\(\)\"\'\-\w:\/\.]{0,64}/
    $eval_requests = /eval\(requests\.get[\(\)\"\'\-\w:\/\.]{0,64}/
	$eval_urllib = /exec\(urllib\.request\.urlopen\([\(\)\"\'\-\w:\/\.]{0,64}\).read\(\)/
	$exec_urllib = /exec\(urllib\.request\.urlopen\([\(\)\"\'\-\w:\/\.]{0,64}\).read\(\)/
  condition:
    filesize < 65535 and $http and any of ($e*)
}

rule remote_eval_close : critical {
  meta:
    description = "Evaluates remotely sourced code"
    hash_2019_active_controller_middleware = "9a85e7aee672b1258b3d4606f700497d351dd1e1117ceb0e818bfea7922b9a96"
    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
    hash_2023_0_0_7_payload = "bb6ca6bfd157c39f4ec27589499d3baaa9d1b570e622722cb9bddfff25127ac9"
  strings:
    $eval = "eval("
    $header = /(GET|POST|COOKIE|cookie)/
  condition:
    math.max(@header, @eval) - math.min(@header, @eval) < 96
}

rule python_exec_near_requests : critical {
  meta:
    description = "Executes code from encrypted remote content"
    hash_2023_EoerbIsjxqyV_init = "76e641b1de6630dc61e875a874c74bb4f2ba7d42dc97caaa5a6926682313cd31"
    hash_2022_colorsapi = "da4a034f20cb7d642e9b61daa9cfa7a63538a8323ce862c87ac1904c89c9acdf"
    hash_2022_colorsapi_6_6_7_setup = "9622c5166933c01121a5c06974c6159abe1e25f3d19637a00bc77f1d832559a5"
  strings:
    $exec = "exec("
    $requests = "requests.get"
  condition:
    all of them and math.abs(@requests - @exec) <= 256
}

rule python_eval_near_requests : critical {
  meta:
    description = "Evaluates code from encrypted remote content"
    hash_2024_analyze_me_1_0_0_setup = "ca9c74630ed814053220129ee6c43668e66898983d9be5e34b406bbd3ad95b1e"
  strings:
    $eval = "eval("
    $requests = "requests.get"
  condition:
    all of them and math.abs(@requests - @eval) <= 256
}

rule python_exec_near_get : critical {
  meta:
    description = "Executes code from encrypted content"
    hash_2024_xFileSyncerx_xfilesyncerx = "c68e907642a8462c6b82a50bf4fde82bbf71245ab4edace246dd341dc72e5867"
    hash_2024_2024_d3duct1v_xfilesyncerx = "b87023e546bcbde77dae065ad3634e7a6bd4cc6056167a6ed348eee6f2a168ae"
  strings:
    $f_exec = "exec("
    $f_requests = /[a-z]{1,4}.get\(/ fullword
    $not_pyparser = "All of the heavy"
    $not_pyparser2 = "lifting is handled by pyparsing (http://pyparsing.sf.net)."
    $not_sparser = "sparser.py [options] filename"
  condition:
    all of ($f*) and math.abs(@f_requests - @f_exec) <= 32 and none of ($not*)
}

rule python_eval_near_get : critical {
  meta:
    description = "Executes code from encrypted content"
  strings:
    $eval = "eval("
    $requests = /[a-z]{1,4}.get\(/ fullword
  condition:
    all of them and math.abs(@requests - @eval) <= 32
}

rule php_remote_exec : critical {
  meta:
    description = "Executes code from a remote source"
    credit = "Inspired by DodgyPHP rule in php-malware-finder"
    hash_2023_0xShell = "acf556b26bb0eb193e68a3863662d9707cbf827d84c34fbc8c19d09b8ea811a1"
    hash_2023_0xShell_0xObs = "6391e05c8afc30de1e7980dda872547620754ce55c36da15d4aefae2648a36e5"
    hash_2023_0xShell = "a6f1f9c9180cb77952398e719e4ef083ccac1e54c5242ea2bc6fe63e6ab4bb29"
  strings:
    $php = "<?php"
    $f_execution = /\b(popen|eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase
    $f_execution2 = /\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase
    $f_execution3 = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff)\s*\(\s*([^,]+\s*,?)+\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))\s*\[[^]]+\]\s*\)+\s*;/ nocase
    $f_register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/
    $not_php = "Copyright (c) The PHP Group"
    $not_php2 = "This source file is subject to version 3.01 of the PHP license"
    $not_php_domain = "@php.net"
    $not_php_id = "/* $Id: bb422e41c0fe4303a4efb3f3657568b74c20cf96 $ */"
  condition:
    filesize < 1048576 and $php and any of ($f*) and none of ($not*)
}
