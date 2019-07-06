import "androguard"

rule test
{
	meta:
		description = "RussianBanker"

	condition:
	(androguard.filter("android.intent.action.QUICKBOOT_POWERON") and androguard.filter("android.provider.Telephony.WAP_PUSH_DELIVER") and
	androguard.filter("android.provider.Telephony.SMS_DELIVER") and
	androguard.filter("android.provider.Telephony.SMS_RECEIVED") and
	androguard.filter("android.intent.action.SENDTO") and androguard.filter("android.intent.action.BOOT_COMPLETED") and
	androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")and
	androguard.filter("android.intent.action.MAIN") and
	androguard.filter("android.intent.action.SEND")) or (androguard.url(/7880/) or androguard.url(/6280/))
		
}