rule SMSReviever : banker
{
	meta:
		description = "To found apps with a typo error, is classified too as ibanking"
		sample = "6903ce617a12e2a74a3572891e1df11e5d831632fae075fa20c96210d9dcd507"

	strings:
	$a = {53 6D 73 52 65 63 69 65 76 65 72 75 70 64 61 74 65} //SmsRevieverupdate

	condition:
		$a
		
}