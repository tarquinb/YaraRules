import "androguard"
import "file"
import "cuckoo"

rule jiagu_apktoolplus : packer
{
    meta:
        description = "Jiagu (ApkToolPlus)"
        sample      = ""
        url         = ""


    strings:
        $a = "assets/jiagu_data.bin"
        $b = "assets/sign.bin"
        $c = "libapktoolplus_jiagu.so"

    condition:
        all of them
}