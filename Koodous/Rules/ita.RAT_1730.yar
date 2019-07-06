import "androguard"
import "file"


rule citrusRAT {
	meta:
		description = "Ruleset to detect an Italian RAT." 
		sample = "f26658419a9113b0b79ecd58966aee93deec77ea713ff37af36c249002419310" 
	
	strings:
		$a = "/system/bin/screenrecord /sdcard/example.mp4"
		$b = "/system/bin/rm /sdcard/img.png"
		$c = "2.117.118.97"
		$d = "monitorSMSAttivo"
		$f = "+393482877835"
		$g = "fin qui OK 7"
		$h = "/system/xbin/"
	condition:
		all of them 

}