
import "androguard"


rule minecraft

{

    condition:

        ( androguard.app_name("Minecraft: Pocket Edition") or 

            androguard.app_name("Minecraft - Pocket Edition") )

        and not androguard.package_name("com.mojang.minecraftpe")

}