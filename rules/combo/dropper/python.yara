
rule http_open_write_system : high {
  meta:
    description = "fetch and execute programs"
    hash_2022_laysound_4_5_2_setup = "4465bbf91efedb996c80c773494295ae3bff27c0fff139c6aefdb9efbdf7d078"
    hash_2023_JokerSpy_shared = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"
    hash_2023_JokerSpy_shared = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"
  strings:
    $http_requests_get = "requests.get" fullword
    $http_requests_post = "requests.post" fullword
    $http_urllib = "urllib.request" fullword
    $http_urlopen = "urlopen" fullword
    $open = "open("
    $write = "write("
    $system = "os.system" fullword
    $sys_popen = "os.popen" fullword
    $sys_sub = "subprocess" fullword
  condition:
    filesize < 16384 and any of ($h*) and $open and $write and any of ($sys*)
}

rule setuptools_dropper : critical {
  meta:
    description = "setuptools script that fetches and executes"
    hash_2022_laysound_4_5_2_setup = "4465bbf91efedb996c80c773494295ae3bff27c0fff139c6aefdb9efbdf7d078"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2022_selenuim_4_4_2_setup = "5c5e1d934dbcbb635f84b443bc885c9ba347babc851cd225d2e18eadc111ecf0"
  strings:
    $setup = "setup("
    $setuptools = "setuptools" fullword
    $http_requests = "requests.get" fullword
    $http_requests_post = "requests.post" fullword
    $http_urrlib = "urllib.request" fullword
    $http_urlopen = "urlopen" fullword
    $system = "os.system" fullword
    $sys_popen = "os.popen" fullword
    $sys_sub = "subprocess" fullword
  condition:
    all of ($setup*) and any of ($http*) and any of ($sys*)
}
