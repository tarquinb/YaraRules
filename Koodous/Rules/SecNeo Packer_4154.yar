import "androguard"
import "file"
import "cuckoo"

rule secneo : packer
{
  meta:
    description = "SecNeo"
    url = "http://www.secneo.com"

  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"

  condition:
    any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}