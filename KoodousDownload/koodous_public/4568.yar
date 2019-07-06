import "androguard"

rule UPIPINActivity
{
	meta:
		description = "All UPI Rules"	

	condition:
		androguard.activity("org.npci.upi.security.pinactivitycomponent.GetCredential")		
		
}

rule AePSActivity
{
	meta:
		description = "All UPI Rules"	

	condition:
		androguard.activity("com.tcs.merchant.cags.UPIPaymentFragment")		
}