import "androguard"
import "file"
import "cuckoo"


rule allatori_v_6 : obfuscator
{
  meta:
    description = "Allatori v.6.x"


    strings:
        // classes, fields and methods like: IiIIiiiiIIiI
        //$a = /[iI]{12}/
        $b = { 00 0C (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) (49|69) 00 }

    condition:
        any of them
}