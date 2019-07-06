import "androguard"
import "file"
import "cuckoo"

rule dexprotector : packer
{
 /**
 * DexProtector v6.x.x :- Demo,Standard,Business Edition (https://dexprotector.com)
 **/
  meta:
    author = "Jasi2169"
    description = "DexProtector"

  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"

  condition:
    any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}