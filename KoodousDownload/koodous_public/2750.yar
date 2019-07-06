import "androguard"
import "file"
import "cuckoo"


rule Android_NetWire
{
	meta:
		description = "This rule detects the NetWire Android RAT, used to show all Yara rules potential"
		sample = "41c4c293dd5a26dc65b2d289b64f9cb8019358d296b413c192ba8f1fae22533e "

	strings:
		$a = {41 68 4D 79 74 68}
	condition:

		androguard.url(/\?model=/) and $a
	
		and androguard.permission(/android.permission.ACCESS_FINE_LOCATION/)
and androguard.permission(/android.permission.SEND_SMS/)
and androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
and androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
and androguard.permission(/android.permission.READ_PHONE_STATE/)
and androguard.permission(/android.permission.CAMERA/)
and androguard.permission(/android.permission.RECORD_AUDIO/)
and androguard.permission(/android.permission.WAKE_LOCK/)
and androguard.permission(/android.permission.READ_CALL_LOG/)
and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
and androguard.permission(/android.permission.INTERNET/)
and androguard.permission(/android.permission.MODIFY_AUDIO_SETTINGS/)
and androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
and androguard.permission(/android.permission.READ_CONTACTS/)
and androguard.permission(/android.permission.READ_SMS/)
		
}