import "androguard"
import "file"
import "cuckoo"


rule apkpacker : packer
{
    meta:
        description = "ApkPacker"

    strings:
        $a = "assets/ApkPacker/apkPackerConfiguration"
        $b = "assets/ApkPacker/classes.dex"
        //$c = "assets/config.txt"
        //$d = "assets/sht.txt"

    condition:
        all of them
}