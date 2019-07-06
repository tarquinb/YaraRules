import "androguard"
import "file"
import "cuckoo"


rule kony : packer
{
  meta:
    description = "Kony"
	  url = "http://www.kony.com/"

  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"

  condition:
    $lib and $decrypt_keys and $encrypted_js
}