import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "https://blog.fortinet.com/2017/01/26/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-i-debugging-in-the-scope-of-native-layer"

	strings:
		$a = /com.secshell/
		$b = "secData0.jar"
		$c = "DexInstall"
		$d = "libSecShell.so"

	condition:
 		2 of them
}