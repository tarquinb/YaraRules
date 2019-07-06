import "androguard"

rule TOAST
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects TOAST Malware"
		
	strings:
		$a1 = "TYPE_TOAST"
		$a2 = "TOAST_WINDOW_TIMEOUT"
		$a3 = "TYPE_SYSTEM_OVERLAY"
		$a4 = "TYPE_SECURE_SYSTEM_OVERLAY"
	condition:
		all of them
		
}