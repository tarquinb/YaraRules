import "androguard"


rule Slempo : targeting installed Apps
{
	meta:
		description = "Banker 'Slempo' targeting installed Apps with Overlay"

	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#block_numbers"
		$command_4 = "#wipe_data"
		
		$installedAppsMethod = "getInstalledAppsList"
		
	condition:
		3 of ($command_*)
		and $installedAppsMethod
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule Slempo_2 : targeting MastercardData
{

	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#block_numbers"
		$command_4 = "#wipe_data"
		
		$overlay = "mastercard_securecode_logo"
		
	condition:
		3 of ($command_*)
		and $overlay
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}