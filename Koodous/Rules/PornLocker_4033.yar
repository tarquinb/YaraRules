import "androguard"
import "droidbox"


rule PornLocker
{
	meta:
		description = "PornLocker"
		family = "Ransom"

	condition:
		(androguard.url("http://accounts.google.com") or 
		androguard.url("http://cnn.com") or 
		androguard.url("http://google.com") or 
		androguard.url("api4goserver.com/den") or 
		androguard.url("http://play.google.com") or 
		androguard.url("hhttp://play.google.com") or 
		androguard.url("http://hotgraderpornprivate.eu") or 
		androguard.url("http://youtube.com") or 
		androguard.url("http://pornhub.com") or 
		androguard.url("http://amazon.com") or
		androguard.url("http://ns.adobe.com/xap/1.0/") or 
		androguard.url("http://google.com/search")) and
		(androguard.activity(/DerekMii/) or
		androguard.activity(/BodrDobr/) or
		androguard.activity(/DamaProsit/) or
		androguard.activity(/WodkTiva/)) and		
		droidbox.written.filename(/systema.xml/)		
}