import "hash"

rule TFC_md5 {

	meta:
	Description= "TFC team Hash SHA256"
	author = "TFC"
	date = "2021-03-21"
	condition:
	hash.md5(0,filesize) =="E7DAADA03E4BB7AF7F9824DDC4C10A50"
	
}

rule TFC_SHA256 {

	meta:
	Description= "TFC team Hash SHA256"
	author = "TFC"
	date = "2021-03-21"
	condition:
	hash.sha256(0,filesize) =="7E68EB75A99CF8C79EB662F772310988F891743E91717C39B8B6CAA8C9038684"
	
}
