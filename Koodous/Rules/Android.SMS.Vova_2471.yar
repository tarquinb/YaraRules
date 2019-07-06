import "androguard"

rule LocationStealer
{
	meta:
		description = "This rule detects SMS based trojans stealing location"
		sample = "e300bf8af65a58ec7dbe0602e09b24e75c2a98414e40a4bf15ddb66e78af5008"

	strings:
		$str_1 = "vova-set"
		$str_2 = "low battery"
		$str_3 = "vova-change"
		$str_4 = "vova-reset"


	condition:
		(androguard.package_name("com.service.locationservice") and
		androguard.certificate.sha1("4D5B2813770A367C8821A7024CD6DC5319A7E1C7")) or
		(androguard.permission(/android.permission.INTERNET/) and
		 androguard.permission(/android.permission.SEND_SMS/) and
		 androguard.permission(/android.permission.READ_SMS/) and 
		 all of them )
}