import "androguard"
import "file"
import "cuckoo"


rule alibaba : packer
{
  meta:
    description = "Alibaba"

  strings:
    $lib = "libmobisec.so"

  condition:
    $lib
}