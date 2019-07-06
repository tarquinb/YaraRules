rule slempo
{

	meta:
			description = "SLEMPO"
			
	strings:
			$a = "#INTERCEPTED_SMS_START"
			$b = "#INTERCEPTED_SMS_STAR" 
			$c = "#block_numbers" 
			$d = "#wipe_data"
				
	condition:
			all of them
}