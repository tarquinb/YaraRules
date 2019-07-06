
rule libAPKProtect : packer

{

    meta:

        description = "Packer libAPKProtect"


    strings:

        $a = "APKMainAPP"

        $b = "libAPKProtect"


    condition:

        any of them

}


rule libprotectClass : packer

{

    meta:

        description = "Packer libProtect"


    strings:

        $a = "libprotectClass"


    condition:

        $a

}