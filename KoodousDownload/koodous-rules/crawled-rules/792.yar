
import "androguard"



rule SMSFraud : chinese

{

    meta:

        description = "Simulate apps with chinese name to make sms fraud."

        sample = "64f4357235978f15e4da5fa8514393cf9e81fc33df9faa8ca9b37eef2aaaaaf7"



    condition:

        androguard.certificate.sha1("24C0F2D7A3178A5531C73C0993A467BE1A4AF094")

}