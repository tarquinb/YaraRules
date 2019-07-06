import "androguard"
import "droidbox"

rule sms_malwares
{
	meta:
		description = "SMS malwares catcher"

	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		and not androguard.permission(/android.permission.INTERNET/)
		and droidbox.sendsms(/./)
		
}