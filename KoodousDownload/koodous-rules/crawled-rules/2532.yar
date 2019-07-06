
import "androguard"


rule Fake_Hill_Climb2

{

  meta:

      Author = "https://twitter.com/SadFud75"

      Info = "Detection of fake hill climb racing 2 apps"

  condition:

      androguard.app_name("Hill Climb Racing 2") and not androguard.certificate.sha1("F0FDF0136D03383BA4B2BE81A14CD4B778FB1F6C")

}