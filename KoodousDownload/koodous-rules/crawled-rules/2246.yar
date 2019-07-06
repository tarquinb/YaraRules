
rule Trojan_Banker4:Marcher {


    strings:

        $ = "a!v!g.!a!n!t!i!vi!ru!s"

        $ = "a!vg!.!a!n!t!i!v!i!r!u!s"

        $ = "a!vg!.an!ti!vi!r!us!"

        $ = "a!vg.a!n!t!i!v!irus!"

        $ = "av!g!.!a!n!ti!v!i!r!us"

        $ = "av!g.!an!ti!v!i!ru!s!"

        $ = "a!vg.!a!nt!i!v!irus"

        $ = "avg!.!a!n!tivi!ru!s!"

        $ = "avg.!a!n!t!i!v!i!r!u!s"

        $ = "a!v!g.a!n!tiv!i!ru!s"



    condition:

        1 of ($)



}