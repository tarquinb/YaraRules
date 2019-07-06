import "androguard"


rule Marcher : Targeting German Banks
{
	meta:
        description = "Trojan 'Marcher' targeting German Banks"
	
	strings:
		$target1 = ".starfinanz." nocase
		$target2 = ".fiducia." nocase
		$target3 = ".dkb." nocase
		$target4 = ".postbank." nocase
		$target5 = ".dkbpushtan" nocase
		
		$configC2 = "%API_URL%%PARAM%" nocase

	condition:
		1 of ($target*) 
		and $configC2 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}