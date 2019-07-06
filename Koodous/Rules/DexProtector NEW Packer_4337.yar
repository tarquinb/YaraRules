import "androguard"
import "file"
import "cuckoo"



rule dexprotector_new : packer
{
  meta:
    description = "DexProtector"

 strings:
    $encrptlib_1 = /assets\/[A-Za-z0-9.]{2,50}\.arm\-v7\.so\.dat/
    $encrptlib_2 = /assets\/[A-Za-z0-9.]{2,50}\.arm\-v8\.so\.dat/
    $encrptlib_3 = /assets\/[A-Za-z0-9.]{2,50}\.arm\.so\.dat/
    $encrptlib_4 = /assets\/[A-Za-z0-9.]{2,50}\.dex\.dat/
    $encrptlib_5 = /assets\/[A-Za-z0-9.]{2,50}\.x86\.so\.dat/
    $encrptlib_6 = /assets\/[A-Za-z0-9.]{2,50}\.x86\_64\.so\.dat/

    $encrptcustom = /assets\/[A-Za-z0-9.]{2,50}\.mp3/
	
	$a_1 = "assets/dp.arm.so.dat"
    $a_2 = "assets/dp.arm-v7.so.dat"
    $a_3 = "assets/dp.arm-v8.so.dat"
    $a_4 = "assets/dp.x86.so.dat"
    $a_5 = "assets/dp.mp3"

  condition:
    2 of ($encrptlib_*) and $encrptcustom and
	not any of ($a_*)
}