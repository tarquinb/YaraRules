import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects apps with bluetooth permissions"
		

	condition:
		androguard.permission(/android.permission.BLUETOOTH/) or
		androguard.permission(/android.permission.BLUETOOTH_ADMIN/)
		
}