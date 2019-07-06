import "androguard"
import "file"
import "cuckoo"


rule lic_branch_details
{
	meta:
		description = "This rule detects apps that claim to provide LIC branch details"
		sample = "111491fcdfa5871f617c42e259789b2f"

	strings:
		$a_1 = "startAppWall"
		$a_2 = "startLandingPageAd"
		$a_3 = "sendUserInfo"
		
		
	condition:
		all of ($a_*)
		
}