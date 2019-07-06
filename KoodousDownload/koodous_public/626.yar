import "androguard"

rule minsdktest
{
	meta:
		description = "minsdkversion test grabber"


	strings:
		$a = /minSdkVersion/i

	condition:
		$a
		
}