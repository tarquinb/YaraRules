import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "First rule used to detect certain permissions"

	condition:

		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		
		
}