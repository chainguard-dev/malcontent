rule Malicious_MoveIt_Webshell {
    meta:
        description = "Rule to identify a specific malicious webshell (human2.aspx) associated with exploitation of the MOVEit vulnerability"
        author = "Anthony Smith, Huntress"

    strings:
        $aspTag = "<%@"
        $misspelling = "azureAccout" wide ascii fullword
        //Hard-coded misspelled azureAccout
        $requestVariable1 = "X-siLock-Comment" wide ascii fullword
        $requestVariable2 = "X-siLock-Step1" wide ascii fullword
        $requestVariable3 = "X-siLock-Step2" wide ascii fullword
        $requestVariable4 = "X-siLock-Step3" wide ascii fullword
        //Request variables are used to interact with multiple parts of the webshell

    condition:
        $aspTag at 0 and filesize > 6KB and filesize < 9KB and ($misspelling or $requestVariable1 or $requestVariable2 or $requestVariable3 or $requestVariable4)
}
