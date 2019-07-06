rule Android_BANKER_JSM

{
        meta:
                description = "Esta regla detecta Malware Tipo Banker SlempoService"

        strings:
                $a = "Lorg/slempo/service/MessageReceiver" wide ascii
                $b = "Lorg/slempo/service/MyApplication" wide ascii
                $c = "*Lorg/slempo/service/MyDeviceAdminReceiver" wide ascii
                $d = "Lorg/slempo/service/SDCardServiceStarter" wide ascii
                $e = "#Lorg/slempo/service/ServiceStarter" wide ascii

        condition:
                $a or $b or $c or $d or $e
				}