
rule rc4_constants : notable {
    meta:
        descrption = "Identify constants used by the ARC4 cryptographic algorithm."
        author = "@shellcromancer <root@shellcromancer.io>"
        version = "0.1"
        date = "2022-01-03"
        reference = "https://www.goggleheadedhacker.com/blog/post/reversing-crypto-functions#identifying-rc4-in-assembly"
        reference = "https://0xc0decafe.com/detect-rc4-encryption-in-malicious-binaries/"
        reference = "https://blog.talosintelligence.com/2014/06/an-introduction-to-recognizing-and.html"
    strings:
        // optmized constants used by John 
        // https://github.com/openwall/john/blob/b81ed703ceb7ca62df50c2fa0d4ea366ef713a4a/run/opencl/opencl_rc4.h#L32-L47 
        // https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'%5E%7B'%7D,'',false,false,false,false)Find_/_Replace(%7B'option':'Regex','string':';$'%7D,'',true,false,true,false)Remove_whitespace(true,true,true,true,true,false)Split(',','%5C%5Cn')Find_/_Replace(%7B'option':'Regex','string':'0x'%7D,'$optx%20%3D%20%7B',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'%5C%5Cn'%7D,'%7D%5C%5Cn',true,false,true,false)&input=eyAweDAzMDIwMTAwLCAweDA3MDYwNTA0LCAweDBiMGEwOTA4LCAweDBmMGUwZDBjLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMHgxMzEyMTExMCwgMHgxNzE2MTUxNCwgMHgxYjFhMTkxOCwgMHgxZjFlMWQxYywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDB4MjMyMjIxMjAsIDB4MjcyNjI1MjQsIDB4MmIyYTI5MjgsIDB4MmYyZTJkMmMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAweDMzMzIzMTMwLCAweDM3MzYzNTM0LCAweDNiM2EzOTM4LCAweDNmM2UzZDNjLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMHg0MzQyNDE0MCwgMHg0NzQ2NDU0NCwgMHg0YjRhNDk0OCwgMHg0ZjRlNGQ0YywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDB4NTM1MjUxNTAsIDB4NTc1NjU1NTQsIDB4NWI1YTU5NTgsIDB4NWY1ZTVkNWMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAweDYzNjI2MTYwLCAweDY3NjY2NTY0LCAweDZiNmE2OTY4LCAweDZmNmU2ZDZjLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMHg3MzcyNzE3MCwgMHg3Nzc2NzU3NCwgMHg3YjdhNzk3OCwgMHg3ZjdlN2Q3YywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDB4ODM4MjgxODAsIDB4ODc4Njg1ODQsIDB4OGI4YTg5ODgsIDB4OGY4ZThkOGMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAweDkzOTI5MTkwLCAweDk3OTY5NTk0LCAweDliOWE5OTk4LCAweDlmOWU5ZDljLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMHhhM2EyYTFhMCwgMHhhN2E2YTVhNCwgMHhhYmFhYTlhOCwgMHhhZmFlYWRhYywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDB4YjNiMmIxYjAsIDB4YjdiNmI1YjQsIDB4YmJiYWI5YjgsIDB4YmZiZWJkYmMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAweGMzYzJjMWMwLCAweGM3YzZjNWM0LCAweGNiY2FjOWM4LCAweGNmY2VjZGNjLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMHhkM2QyZDFkMCwgMHhkN2Q2ZDVkNCwgMHhkYmRhZDlkOCwgMHhkZmRlZGRkYywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDB4ZTNlMmUxZTAsIDB4ZTdlNmU1ZTQsIDB4ZWJlYWU5ZTgsIDB4ZWZlZWVkZWMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAweGYzZjJmMWYwLCAweGY3ZjZmNWY0LCAweGZiZmFmOWY4LCAweGZmZmVmZGZjIH07
        $opt0 = {03020100}
        $opt1 = {07060504}
        $opt2 = {0b0a0908}
        $opt3 = {0f0e0d0c}
        $opt4 = {13121110}
        $opt5 = {17161514}
        $opt6 = {1b1a1918}
        $opt7 = {1f1e1d1c}
        $opt8 = {23222120}
        $opt9 = {27262524}
        $opt10 = {2b2a2928}
        $opt11 = {2f2e2d2c}
        $opt12 = {33323130}
        $opt13 = {37363534}
        $opt14 = {3b3a3938}
        $opt15 = {3f3e3d3c}
        $opt16 = {43424140}
        $opt17 = {47464544}
        $opt18 = {4b4a4948}
        $opt19 = {4f4e4d4c}
        $opt20 = {53525150}
        $opt21 = {57565554}
        $opt22 = {5b5a5958}
        $opt23 = {5f5e5d5c}
        $opt24 = {67666564}
        $opt25 = {6b6a6968}
        $opt26 = {6f6e6d6c}
        $opt27 = {73727170}
        $opt28 = {77767574}
        $opt29 = {7b7a7978}
        $opt30 = {7f7e7d7c}
        $opt31 = {83828180}
        $opt32 = {87868584}
        $opt33 = {8b8a8988}
        $opt34 = {8f8e8d8c}
        $opt35 = {93929190}
        $opt36 = {97969594}
        $opt37 = {9b9a9998}
        $opt38 = {9f9e9d9c}
        $opt39 = {a3a2a1a0}
        $opt40 = {a7a6a5a4}
        $opt41 = {abaaa9a8}
        $opt42 = {afaeadac}
        $opt43 = {b3b2b1b0}
        $opt44 = {b7b6b5b4}
        $opt45 = {bbbab9b8}
        $opt46 = {bfbebdbc}
        $opt47 = {c3c2c1c0}
        $opt48 = {c7c6c5c4}
        $opt49 = {cbcac9c8}
        $opt50 = {cfcecdcc}
        $opt51 = {d3d2d1d0}
        $opt52 = {d7d6d5d4}
        $opt53 = {dbdad9d8}
        $opt54 = {dfdedddc}
        $opt55 = {e3e2e1e0}
        $opt56 = {e7e6e5e4}
        $opt57 = {ebeae9e8}
        $opt58 = {efeeedec}
        $opt59 = {f3f2f1f0}
        $opt60 = {f7f6f5f4}
        $opt61 = {fbfaf9f8}
        $opt62 = {fffefdfc}
        $opt63 = {63626160}
    condition:
        80% of ($opt*)
}