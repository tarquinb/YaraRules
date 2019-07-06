rule banker: generic
{
	meta:
		description = "This rule detects the Generic banker asking for credit card information where GooglePlay is launched"
		sample = "4782faa6ae60a1d31737385196deeffc920cfb6c4f1151947f082c5d78846549"

	strings:
		$visa_1 = "res/drawable/cvc_visa.gifPK"
		$visa_2 = "cvc_visa"
		
		$mastercard_1 = "res/drawable/cvc_mastercard.gifPK"
		$mastercard_2 = "cvc_mastercard"
		
		$google_play = "Google Play"
		

	condition:
		(all of ($visa_*) or all of ($mastercard_*)) and $google_play
		
}