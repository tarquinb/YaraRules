import "androguard"


rule postepay_smsFraud
{
	meta:
		description = "Yara detection for PostePay SMS-fraud"

	condition:		
		
		androguard.package_name("me.help.botfix") and
		androguard.certificate.sha1("F3B7734A4BADE62AD30FF4FA403675061B8553FF") and
		androguard.receiver(/\.SmsListener/) and 
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) 
		
}