
import "androguard"


rule Fake_Flash

{

  meta:

       description = "Detects fake flash apps"

   condition:

       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) //and not

       //(androguard.app_name(/acrobat/) or androguard.app_name(/pdf/))

}