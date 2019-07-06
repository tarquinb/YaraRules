import "androguard"

rule sms_malwares_nograiny
{
	meta:
		description = "SMS malwares catcher"

	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		
}