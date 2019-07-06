import "androguard"



rule PluginPanthom
{
	meta:
		description = "This rule detects pluginpanthom"
		report = "From Palo Alto Networks http://researchcenter.paloaltonetworks.com/2016/11/unit42-pluginphantom-new-android-trojan-abuses-droidplugin-framework/"
	strings:
		$a = "1519j010g4.iok.la"
		$b = "58.222.39.215:8088/dmrcandroid/ws/httpsData/command"


	condition:
		($a and $b) or (
		androguard.url("1519j010g4.iok.la") and
		androguard.url("58.222.39.215:8088/dmrcandroid/ws/httpsData/command")
		)
		
}