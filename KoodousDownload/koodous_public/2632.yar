import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule is checking for SMS sending without creds/authentication"

	condition:

		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CHANGE_CONFIGURATION/) and
		not androguard.permission(/android.permission.AUTHENTICATE_ACCOUNTS/) and
		not androguard.permission(/android.permission.USE_CREDENTIALS/) and
		not androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		not androguard.permission(/android.permission.BLUETOOTH_ADMIN/)

		
}