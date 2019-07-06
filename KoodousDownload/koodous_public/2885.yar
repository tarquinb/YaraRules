rule  practica4_slempo
{
	meta:
		description=  "BANKED_SLEMPO"
	strings:
		$a= "slempo"
		$b= "intercept_sms_start"
		$c= "unblock_all_number"
	condition:
		$a and $b and $c
}