import "androguard"

rule collectors
{
	meta:
		description = "Filter for remote controlled malwares"

	condition:
		androguard.permission(/android.permission.INTERNET/)
		and androguard.permission(/android.permission.READ_SMS/)
		and androguard.permission(/android.permission.READ_PHONE_STATE/)
		and androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		and androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
		and not androguard.permission(/android.permission.SEND_SMS/)
}