import "androguard"

rule UPIPINActivity
{
	meta:
		description = "All UPI PIN Activity apps"	

	condition:
		androguard.activity("org.npci.upi.security.pinactivitycomponent.GetCredential")		
		
}

rule AePSActivity
{
	meta:
		description = "All TCS AePS UPI apps"	

	condition:
		androguard.activity("com.tcs.merchant.cags.UPIPaymentFragment")		
}