rule adware
{
	meta:
		description = "This rule detects ad application, used to show all Yara rules potential"
		sample = "33c61bf9ec395953851594d4595d33e004414ec17044f66858610cdac79b6946"
		sample2 = "d33b7e67696d0f30f4e2c360ce76b56f2ca78f181c456004ed395aaffd7c7f24"
		sample3 = "39b993dc0866075b2d489e98552cbf4f57b810c432b75a9a5df7599901318f4f"

	strings:
		$a = "MobclickAgent"
		$b = "Landroid/graphics/NinePatch;"
		$c = "#FloatService.createFloat(=========)"

	condition:
		all of them
}

rule adware2
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "33c61bf9ec395953851594d4595d33e004414ec17044f66858610cdac79b6946"
		sample2 = "d33b7e67696d0f30f4e2c360ce76b56f2ca78f181c456004ed395aaffd7c7f24"
		sample3 = "39b993dc0866075b2d489e98552cbf4f57b810c432b75a9a5df7599901318f4f"

	strings:
		$a = "missing appkey"
		$b = "/download/.um"
		$c = "noiconads.jar"

	condition:
		all of them
}