import "androguard"
import "file"


rule koodous : official
{
	meta:
		description = "Looks up Toast Overlayer Attacking Apps"

	strings:
		$a = "device_policy"
		$b = "clipboard"
		$c = "power"
		$d = "com.android.packageinstaller"
		$e = "bgAutoInstall"

	condition:
		$a and
		$b and
		$c and 
		$d and 
		$e and
		androguard.activity(/MyAccessibilityServiceTmp/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/)
}