rule basebridge
{
	meta:
		description = "A rule to detect Basebridge app"
		sample = "7f8331158501703c5703acaf189bcdd7cb026c14a453a662cb0dfd8bd49a2a45"
		source = "https://www.f-secure.com/v-descs/trojan_android_basebridge.shtml"

	strings:
		$a = "&HasSimCard="
		$b = "&mobilekey="
		$c = "http://service.sj.91.com/AppCenter/index.aspx"

	condition:
		all of them
		
}