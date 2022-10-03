rule D220930_Webshell_AntSword
{
	meta:
		author = "NCA-KSA"
		description = "suspected antsword webshell"
		score = 70
		date = "2022-09-30"
	strings:
		$a1 = "Jscript" nocase
		$a2 = "eval" nocase
		$a3 = "GetEncoding(" nocase
		$a4 = ".FromBase64String(" nocase
		$a5 = "char(" nocase
	condition:
		filesize < 1KB and all of them
}

rule D220930_Webshell_SharPyShell
{
	meta:
		author = "NCA-KSA"
		description = "suspected SharPyShell webshell"
		score = 70
		date = "2022-09-30"
	strings:
		$a1 = "Import Namespace" nocase
		$a2 = "System.Web" nocase
		$a3 = "System.Reflection" nocase
		$a4 = "c#" nocase
		$a5 = "Request.Form[" nocase
		$a6 = "Assembly.Load(" nocase
		$a7 = "SharPy" nocase
	condition:
		filesize < 40KB and all of them
}

rule D220627_ASPX_CMD_v2_Webshell_ {
	meta:
		author = "NCA-KSA"
		description = "Executing CMD commands in a webshell"
		score = 70
		date = "2022-06-28"
		
	strings:
		$a1 = "FileInfo(" ascii wide nocase
		$a2 = "Upload(" ascii wide nocase
		$a3 = "Convert.FromBase64String(" ascii wide nocase
		$a4 = ".Arguments" ascii wide nocase
		$a5 = ".UseShellExecute" ascii wide nocase
		$a6 = "<%@ Page language=\"c#" ascii wide nocase
		$a7 = ".Start" ascii wide nocase
		$a8 = ".FileName" ascii wide nocase
		$a9 = ".write" ascii wide nocase
		$a10 = "Execute(" ascii wide nocase
		$a11 = "<script runat=" ascii wide nocase
		$a12 = "System.Diagnostics" ascii wide nocase
		$a13 = "Request" ascii wide nocase
		$a14 = "Process" ascii wide nocase
		$a15 = "ProcessStartInfo" ascii wide nocase
		$a16 = "POST" ascii wide nocase
		
	condition:
		filesize < 50KB and
		12 of ($a*) 
}
