import "math"

rule remote_eval: critical {
  meta:
    description = "Evaluates remotely sourced code"
    filetypes   = "py,rb"

  strings:
    $http                = "http"
    $eval_open_ruby      = /eval\(open[\(\)\"\'\-\w:\/\.]{0,64}/
    $eval_http_ruby      = /eval\(Net::HTTP.get.{0,4}[\(\)\"\'\-\w:\/\.]{0,64}/
    $exec_requests       = /exec\(requests\.get[\(\)\"\'\-\w:\/\.]{0,64}/
    $eval_requests       = /eval\(requests\.get[\(\)\"\'\-\w:\/\.]{0,64}/
    $eval_request_urllib = /exec\(urllib\.request\.urlopen\([\(\)\"\'\-\w:\/\.]{0,64}\).read\(\)/
    $exec_request_urllib = /exec\(urllib\.request\.urlopen\([\(\)\"\'\-\w:\/\.]{0,64}\).read\(\)/
    $eval_urllib         = /eval\(urllib\.urlopen\([\(\)\"\'\-\w:\/\.]{0,64}\).read\(\)/
    $exec_urllib         = /exec\(urllib\.urlopen\([\(\)\"\'\-\w:\/\.]{0,64}\).read\(\)/

    $not_open_clip1 = "class ResampledShards2(IterableDataset)"
    $not_open_clip2 = "class SyntheticDataset(Dataset)"

  condition:
    filesize < 65535 and $http and any of ($e*) and none of ($not*)
}

rule remote_eval_close: high {
  meta:
    description = "Evaluates remotely sourced code"
    filetypes   = "php"

  strings:
    $php    = "<?php"
    $eval   = "eval("
    $header = /(GET|POST|COOKIE|cookie)/

  condition:
    filesize < 16KB and $php and math.max(@header, @eval) - math.min(@header, @eval) < 96
}

rule python_exec_near_requests: high {
  meta:
    description = "Executes code from encrypted remote content"
    filetypes   = "py"

  strings:
    $exec     = "exec("
    $requests = "requests.get"

  condition:
    all of them and math.abs(@requests - @exec) <= 256
}

rule python_eval_near_requests: high {
  meta:
    description = "Evaluates code from encrypted remote content"
    filetypes   = "py"

  strings:
    $eval     = "eval("
    $requests = "requests.get"

  condition:
    all of them and math.abs(@requests - @eval) <= 256
}

rule python_exec_near_get: high {
  meta:
    description = "Executes code from encrypted content"
    filetypes   = "py"

  strings:
    $f_exec        = "exec("
    $f_requests    = /[a-z]{1,4}.get\(/ fullword
    $not_pyparser  = "All of the heavy"
    $not_pyparser2 = "lifting is handled by pyparsing (http://pyparsing.sf.net)."
    $not_sparser   = "sparser.py [options] filename"

  condition:
    all of ($f*) and math.abs(@f_requests - @f_exec) <= 32 and none of ($not*)
}

rule python_eval_near_get: high {
  meta:
    description = "Executes code from encrypted content"
    filetypes   = "py"

  strings:
    $eval     = "eval("
    $requests = /[a-z]{1,4}.get\(/ fullword

  condition:
    all of them and math.abs(@requests - @eval) <= 32
}

rule php_remote_exec: critical {
  meta:
    description = "Executes code from a remote source"
    credit      = "Inspired by DodgyPHP rule in php-malware-finder"
    filetypes   = "php"

  strings:
    $php                 = "<?php"
    $f_execution         = /\b(popen|eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase
    $f_execution2        = /\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase
    $f_execution3        = /\b(array_(diff|intersect)_u(key|assoc)|array_udiff)\s*\(\s*([^,]+\s*,?)+\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))\s*\[[^]]+\]\s*\)+\s*;/ nocase
    $f_register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/
    $not_php             = "Copyright (c) The PHP Group"
    $not_php2            = "This source file is subject to version 3.01 of the PHP license"
    $not_php_domain      = "@php.net"
    $not_php_id          = "/* $Id: bb422e41c0fe4303a4efb3f3657568b74c20cf96 $ */"

  condition:
    filesize < 1048576 and $php and any of ($f*) and none of ($not*)
}

rule java_http_replacement_class: high java {
  meta:
    description = "runtime override of a class, possibly downloaded from elsewhere"
    filetypes   = "jar,java"

  strings:
    $replace = "loadReplacementClass"
    $url     = /https*:\/\/\w{1}[\w\.\/\&]{8,64}/

  condition:
    all of them
}
