import "androguard"
import "file"
import "cuckoo"



rule appguard : packer
{
    meta:
        description = "AppGuard"
       
    strings:
        $c = "AppGuard0.jar"
        $d = "AppGuard.dgc"
        $e = "libAppGuard.so"
        $f = "libAppGuard-x86.so"

    condition:
        3 of them
}