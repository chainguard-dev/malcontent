rule python_calls_itself: medium {
  meta:
    description = "Python program executes Python subprocess"

  strings:
    $sub   = /subprocess\.\w{2,10}\(\['python'/
    $popen = /Popen\(\['python'/

  condition:
    any of them
}

rule python_calls_itself_no_window: high {
  meta:
    description = "Python program executes Python subprocess via hidden window"

  strings:
    $subproc = /subprocess\.\w{2,10}\(\['python'.{0,64}CREATE_NO_WINDOW/
    $popen   = /Popen\(\['python'.{0,64}CREATE_NO_WINDOW/

  condition:
    any of them
}
