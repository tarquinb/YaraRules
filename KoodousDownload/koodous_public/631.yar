import "androguard"

rule collectors
{
	meta:
		description = "Filter for private information collecting malwares"

	condition:
		androguard.permission(/android.permission.INTERNET/)
		and androguard.permission(/android.permission.READ_SMS/)
		and androguard.permission(/android.permission.READ_PHONE_STATE/)
		and androguard.permission(/android.permission.CHANGE_NETWORK_STATE/)
		and androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		and androguard.permission(/android.permission.READ_CONTACTS/)
		and androguard.permission(/android.permission.GET_ACCOUNTS/)
		and androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/)
}