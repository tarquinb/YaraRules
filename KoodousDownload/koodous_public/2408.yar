import "androguard"
import "file"
import "cuckoo"


rule Banker : Cosmetiq Targeting German Banks
{
	meta:
        description = "Banker 'Cosmetiq' targeting German Banks"
	
	strings:
		$c2_prefix = "{\"to\":"
		$c2_mid = "\",\"body\":"
		$c2_suffix = "php\"},"
	
		$target1 = "com.starfinanz.smob.android.sfinanzstatus" nocase
		$target2 = "com.starfinanz.smob.android.sbanking" nocase
		$target3 = "de.fiducia.smartphone.android.banking.vr" nocase
		$target4 = "de.dkb.portalapp" nocase
		$target5 = "de.postbank.finanzassistent" nocase
		$target6 = "com.starfinanz.mobile.android.dkbpushtan" nocase
		
		$com1 = "upload_sms"
		$com2 = "send_sms"
		$com3 = "default_sms"
		$com4 = "sms_hook"
		$com5 = "gp_dialog_password"
		$com6 = "gp_password_visa"
		$com7 = "gp_password_master"
		
	condition:
		all of ($c2*)
		and 1 of ($target*) 
		and 2 of ($com*) 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}