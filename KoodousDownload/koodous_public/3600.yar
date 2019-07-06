import "androguard"
import "file"
import "cuckoo"


rule readsms
{
	meta:
		description = "This rule detects read_sms"

	condition:
		androguard.permission(/android.permission.READ_SMS/)
}