import "androguard"
import "droidbox"
import "file"

rule SecondHand
{
  meta:
	description = "Trojan SecondHand"
	
  strings:
    $lib_arm = "lib/armeabi/libsecondhand.so"
    $lib_armv7 = "lib/armeabi-v7a/libsecondhand.so"
	$lib_armv8 = "lib/arm64-v8a/libsecondhand.so"
	$lib_mips = "lib/mips/libsecondhand.so"
	$lib_mips64 = "lib/mips64/libsecondhand.so"
	$lib_x86 = "lib/x86/libsecondhand.so"
	$lib_x64 = "lib/x86_64/libsecondhand.so"

  condition:
    $lib_arm or $lib_armv7 or $lib_armv8 or $lib_mips or $lib_mips64 or $lib_x86 or $lib_x64 or droidbox.library(/libsecondhand\.so/) or droidbox.written.filename("0.xml") or droidbox.written.filename("F.xml")
}