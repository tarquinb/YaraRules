rule redalert {

	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = /wroted data base64/
		$string_3 = /templates_names/
	condition:
		1 of ($string_*)
}