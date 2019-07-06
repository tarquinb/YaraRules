rule Banker2 {
	strings:
		$r1 = "SmsReceiver"
		$r2 = "BootReceiver"
		$r3 = "AdminReceiver"
		$r4 = "AlarmReceiver"
		$r5 = "ServiceDestroyReceiver"
		$r6 = "AdminRightsReceiver"
		$r7 = "MessageReceiver"

		$s1 = "USSDService"
		$s2 = "GPService"
		$s3 = "FDService"
		$s4 = "MainService"
			
		$as1 = "AdminService"
		$as2 = "AdminRightsService"
		
	condition:
	3 of ($r*) and all of ($s*) and 1 of ($as*)
		
}

rule Trojan_SMS:Banker {
	strings:
		$ = "Landroid/telephony/SmsManager"
		$ = "szClassname"
		$ = "szICCONSEND"
		$ = "szModuleSmsStatus"
		$ = "szModuleSmsStatusId"
		$ = "szName"
		$ = "szNomer"
		$ = "szNum"
		$ = "szOk"
		$ = "szTel"
		$ = "szText"
		$ = "szpkgname"

	condition:
		all of them
}