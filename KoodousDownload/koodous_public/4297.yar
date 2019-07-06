rule Xafecopy
{
	meta:
		author = "Ransombleed"
		description = "Xafecopy detection rule"
	strings:
        $a =  "assets/chazhaoanniu.js"
		$a2 = "assets/chuliurl.js"
		$a3 = "assets/monidianji.js"
		$a4 = "assets/shuruyzm.js"
        $b =  "//Your system is optimizing"
        $b2 = "Congratulations, you have a chance to use the world's popular battery tool."
        $b3 = "Clean Up Assistant is a small, stylish, elegant application that can help you focus on the current battery charge percentage of your circumstances Android device, and even can be used as energy saving device."

       
	condition:
		1 of ($a*) or 2 of ($b*)
}