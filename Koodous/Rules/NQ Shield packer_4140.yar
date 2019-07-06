import "androguard"
import "file"
import "cuckoo"


rule nqshield : packer
{
  meta:
    description = "NQ Shield"

  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"

  condition:
    any of ($lib, $lib_sec1, $lib_sec2)
}