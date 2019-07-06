import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Android.Fakebank"

	condition:
		androguard.package_name("com.ibk.smsmanager") or
		androguard.package_name("com.example.kbtest")
		
		
}