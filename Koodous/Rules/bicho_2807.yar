import "androguard"

rule bicho {

	strings:
		$string_1 = /CREATE TABLE IF NOT EXISTS raw_events/
		$string_2 = /com\.google\.firebase\.provider\.FirebaseInitProvider/
	condition:
		1 of ($string_*) and
		androguard.permission(/android.permission.READ_SMS/) and 
		androguard.permission(/android.permission.CAMERA/) and 
		androguard.permission(/com.google.android.c2dm.permission.RECEIVE/) and 
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		
}