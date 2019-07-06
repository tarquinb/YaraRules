import "androguard"

rule chineseSMSSender
{
	condition:
		androguard.package_name("com.android.phonemanager") and
		androguard.permission(/android.permission.SEND_SMS/)
}