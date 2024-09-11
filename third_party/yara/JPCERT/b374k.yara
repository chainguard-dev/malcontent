rule webshell_b374k_str {
     meta:
        description = "Webshell b374k"
        author = "JPCERT/CC Incident Response Group"
        hash = "8c30f0ad13f188cb24481bc28512e8f71fd4188d6c6020cfe0c26f43a8233d91"

     strings:
        $b374k2_1 = "$_COOKIE['b374k']"
        $b374k2_2 = "CrOq1gLF3fYNrLiX+Bs8MoTwT2fQPwXgBXHGL+TaIjfinb3C7cscRMIcYL6AAAAAElFTkSuQmCC"
        $b374k2_3 = "J+CS0xFMxf8Ks6rWAsXd9g2suJf4GzwyhPBPZ9A/BeAFccYv5NoiN+KdvcLtyxxEwhxgvoAAAAASUVORK5CYII="
        $b374k2_4 = "<input class='inputzbut' type='submit' value='Go !' name='submitlogin' style='width:80px;' />"
        $b374k3_1 = "TYvfFXKszKl7t7TkzpzJO8l6zI9ki1soLaypb96wl3/cBydJKPVPWP/wI="
        $b374k3_2 = "atN9HV7ZsuZFAIRngh0oVQKZXb+fgBOdQNKnDsVQvjnz/8="
        $b374kencode = "func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on\";$b374k="

     condition:
       3 of ($b374k2_*) or all of ($b374k3_*) or $b374kencode
}
