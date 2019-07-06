import "androguard"
import "file"
import "cuckoo"


rule DetectOverlayMaleware
{
	meta:
		description = "This rule detects the many overlays"
		

	strings:
		$a = ".Telephony.SMS_RECEIVED"
		$b = ".SYSTEM_ALERT_WINDOW"
		$c = "DEVICE_ADMIN_ENABLED"
		$d = "DEVICE_ADMIN_DISABLE_REQUESTED"
        $e = "ACTION_DEVICE_ADMIN_DISABLE_REQUESTED"
		$f = ".wakeup"
		$g = "device_admin"

	condition:
		$a and $b and $c and $d and $e and $f and $g
		
}