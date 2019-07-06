rule smspay
{
	meta:
		description = "This rule detects smspay trojans"
		sample = "d68e86edd71003e3e64954b0de1ecf225d5bf7bea910010b18c3c70b2482174e"

	strings:
		$a = "Lcom/hz/mama/u;"
		$b = "hjwg16Y0G83C18H9wpMLWi25KDSLyNLA2I509GQ5wydMj2qRYVHjf9fV7Xl9cfcFstlYsOtRAxdUcMOa0nkO1qhsbeEqirQRJmnW0Yub6Yar1FzfWJTlHutV43HJmd8E"
		$c = ", signKey="
		$d = ", sample="

	condition:
		all of them
		
}