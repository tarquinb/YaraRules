
import "androguard"


rule SMSFraude

{

    meta:

        autor = "sadfud"

        description = "Se conecta a un panel desde el que descarga e instala nuevas aplicaciones"

    condition:

        androguard.url(/app\.yx93\.com/)        

}