
import "androguard"


rule Banker_Acecard

{

  meta:

      author = "https://twitter.com/SadFud75"

      more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"

      samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb  53cca0a642d2f120dea289d4c7bd0d644a121252"

  strings:

      $str_1 = "Cardholder name"

      $str_2 = "instagram.php"

  condition:

      ((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19

}