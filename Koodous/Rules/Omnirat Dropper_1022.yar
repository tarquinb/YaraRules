rule omnirat_dropper
{
	meta:
		description = "This rule detects omnirat dropper"
		sample = "0b7e5cca82d33429aa1b81f7ae0a707d30b984c083c4ba033a00d2ca637fa8b1"
		sample2 = "244bcc4d39eed69ae215b5ad977209d87f3b7b81a2fd04b961715170d805b38b"
		reference = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-control-of-devices/"

	strings:
		$a = "/android.engine.apk"
		$b = "21150715091744Z0"

	condition:
		all of them
		
}