import "androguard"
import "file"

rule Final_Signature {   
	meta:
		author = "YaYaGen v0.5_winter18"
		date = "07 Feb 2018 - 17:41:11"
	strings:
		$url1 = "yayagen.com"
		$app_name = "App absolutely inoffensive"
	condition:
		androguard.app_name($app_name)
		and androguard.url($url1)
		and androguard.activity(/Activity_Name/)
		and file.size <= 5MB
		and not file.md5("d367fd26b52353c2cce72af2435bd0d5")
		and ( androguard.number_of_permissions >= 90
			  or androguard.permission(/(SEND|WRITE)_SMS/)
		)		
}