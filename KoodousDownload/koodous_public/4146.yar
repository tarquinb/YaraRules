import "androguard"
import "file"
import "cuckoo"



rule yidun : packer
{
  meta:
    description = "yidun"
	  url = "https://dun.163.com/product/app-protect"

  strings:
    $anti_trick = "Lcom/_" // Class path of anti-trick
    $entry_point = "Lcom/netease/nis/wrapper/Entry"
    $jni_func = "Lcom/netease/nis/wrapper/MyJni"
    $lib = "libnesec.so"

  condition:
    (#lib > 1) or ($anti_trick and $entry_point and $jni_func)
}