import "androguard"


rule add_device_admin_activity : official
{
	meta:
		description = "This rule detects apps that request add device admin activity"
	

	strings:
		$a = "android.app.action.ADD_DEVICE_ADMIN"

	condition:
		androguard.activity(/ACTION_ADD_DEVICE_ADMIN/i) or
		$a 
		
}