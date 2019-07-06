import "androguard"
import "file"
import "cuckoo"


rule ezeeworld
{
	meta:
		description = "This rule detects application including Ezeeworld SDK"

	condition:
		androguard.receiver("com.ezeeworld.b4s.android.sdk.monitor.SystemEventReceiver")
		
}