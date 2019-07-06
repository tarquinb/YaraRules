import "androguard"
import "file"
import "cuckoo"


rule kiro : packer
{
  meta:
    description = "Kiro"

  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"

  condition:
    $kiro_lib and $sbox
}

rule qihoo360 : packer
{
  meta:
    description = "Qihoo 360"

  strings:
    $a = "libprotectClass.so"

  condition:
    $a and
    not kiro
}