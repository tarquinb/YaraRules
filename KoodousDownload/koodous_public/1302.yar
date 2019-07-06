rule SMSSender
{
	meta:
		description = "This rule detects a type of SMSSender trojan"
		sample = "2b69cd97c90080dcdcd2f84ef0d91b1bfd858f8defd3b96fbcabad260f511fe7"
		search = "package_name:com.nys.mm"

	strings:
		$json_1 = "\"tn\":\"%s\",\"user\":\"%s\",\"locale\":\"%s\",\"terminal_version\":\"%s\",\"terminal_resolution\":\"%s\""
		$json_2 = "{\"v\":\"%s\",\"cmd\":\"sms\",\"params\":{\"first_pay_flag\":\"%s\",%s}}"
		$json_3 = "\"IsFetchSms\":\"1\",\"SoundTime\":\"10\",\"LbsTime\":\"3000\",\"SmsPattern\":"
		$fail_msg = "Fail to construct message"
		$code = "9AEKIJM?"
		$func_name = "setDiscount"

	condition:
		all of them
		
}