rule samplep4
{
	meta:
		description=”samplepract”
	string:
		$a=”org/slempo/service”
		$b=”http://185.62.188.32/app/remote”
		$c=”Landroit/telephony/SmsManager”
		$d=”intercept_sms_start”
	Condition:
		$a and ($b or $c $d )
}