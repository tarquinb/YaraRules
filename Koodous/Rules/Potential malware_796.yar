import "androguard"
import "droidbox"

rule potential_malware
{
	meta:
		description = "Potential malware"

	strings:
		$a = "com.example.smsmessaging.TestService"
		$b = "setComponentEnabledSetting"

	condition:
		androguard.permission(/BOOT_COMPLETED/) and
		androguard.permission(/CHANGE_COMPONENT_ENABLED_STATE/) and
		$a and $b
}

/*rule ProcessKiller
{
	meta:
		description = "Process killer"
		
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/)
}*/

rule RootApp
{
	meta:
		description = "Root app"
		
	strings:
		$a = "ROOT_ERROR_FAILED"
		$b = "STEP_EXECUTE"
	
	condition:
		all of them
}