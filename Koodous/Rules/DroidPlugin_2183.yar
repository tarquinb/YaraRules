import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects a string that appears in droidplugin/core/PluginProcessManager"
		sample_based_on = "49ff608d2bdcbc8127302256dc7b92b12ea9449eb96255f9ab4d1da1a0405a1b"

	strings:
		$message_str = "preMakeApplication FAIL"

	condition:
		$message_str
		
}