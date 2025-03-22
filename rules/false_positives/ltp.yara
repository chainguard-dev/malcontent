rule dirty_pipe_test: override {
  meta:
    ELASTIC_Linux_Exploit_CVE_2022_0847_E831C285  = "low"
    SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug15 = "low"

  strings:
    $comment1 = " * Ported into LTP by Yang Xu <xuyang2018.jy@fujitsu.com>"
    $comment2 = " * Proof-of-concept exploit for the Dirty Pipe"
    $comment3 = " * vulnerability (CVE-2022-0847) caused by an uninitialized"
    $comment4 = " * \" pipe_buffer.flags \" variable.  It demonstrates how to overwrite any"
    $comment5 = " * Example: ./write_anything /root/.ssh/authorized_keys 1 $'\nssh-ed25519 AAA......\n'"
    $comment6 = " * Further explanation: https://dirtypipe.cm4all.com/"

  condition:
    filesize < 8192 and all of them
}
