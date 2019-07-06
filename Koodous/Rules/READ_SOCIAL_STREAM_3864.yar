import "androguard"
import "file"
import "cuckoo"


rule storage
{
	meta:
		description = "This rule detects READ_SOCIAL_STREAM"

	condition:
		androguard.permission(/android.permission.READ_SOCIAL_STREAM/)
}