import "androguard"
import "file"
import "cuckoo"

rule baidu : packer
{
  meta:
    description = "Baidu"

  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"

  condition:
    ($lib or $encrypted)
}