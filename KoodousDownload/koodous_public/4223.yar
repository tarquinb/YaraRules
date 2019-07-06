import "androguard"
import "file"
import "cuckoo"


rule rule1 : mmarrkv_misc
{
	meta:
		description = "Test rule"

	condition:
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/BIND_ACCESSIBILITY_SERVICE/)
		
}