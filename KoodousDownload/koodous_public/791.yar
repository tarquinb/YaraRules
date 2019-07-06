import "androguard"



rule SMSFraud : russian_dev
{
	meta:
		sample = "f9a86f8a345dd88f87efe51fef3eb32a7631b6c56cbbe019faa114f2d2e9a3ac"

	condition:
		androguard.certificate.sha1("7E209CBB95787A9F4E37ED943E8349087859DA73") or
		androguard.certificate.sha1("3D725C7115302C206ABDD0DA85D67AD546E4A076") or
		androguard.certificate.sha1("AC2D0CFAB11A82705908B88F57854F721C7D2E4E") or
		androguard.certificate.sha1("F394D49E025FA95C38394BB05B26E6CAB9DF0A85") or
		androguard.certificate.sha1("224DE2C3B80A52C08B24A0594EDD6C0A0A14F0D2") or
		androguard.certificate.sha1("CF240D24D441F0A2808E6E5A0203AC05ACF0D10C")
}