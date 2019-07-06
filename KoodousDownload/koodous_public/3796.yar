import "androguard"

rule DroidRooter2
{
	meta:
		author = "Tom_Sara"
		date = "02-Nov-2017"
		description = "This rule try to detects DroidRooter Variant"
		
	condition:
		
		androguard.permission(/android.permission.ACCESS_MOCK_LOCATION/i) and 
		androguard.permission(/android.permission.USE_CREDENTIALS/i) and 
		androguard.permission(/android.permission.CLEAR_APP_CACHE/i)
}