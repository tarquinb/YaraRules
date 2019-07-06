import "androguard"
import "file"
import "cuckoo"


rule storage
{
	meta:
		description = "This rule detects READ_EXTERNAL_STORAGE"

	condition:
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
}