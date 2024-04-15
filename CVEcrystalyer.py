import requests
import sys
import re
import argparse

parser = argparse.ArgumentParser(prog="python3 CVEcrystalyer.py", usage="%(prog)s [options]")
parser.add_argument("-r",metavar="file",nargs='*', help="Get CVE-s from file, e.g. retire.js")
parser.add_argument("-c", metavar="cve", nargs='*', help="Input one CVE e.g. CVE-1111-2222")
args = parser.parse_args()

border = "#"*50


def get_cve_data(cve_id):
	req = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+ cve_id)
	if req.status_code != 200:
		print("[-] Error occured fetching CVE data status code:",req.status_code)
	else:

		#get response text
		regx = req.text

		print(border)
		print("[+] Current CVE:",cve_id)

		#Description
		x = re.search("{\"lang\":\"en\",\"value\":\"(.*?)\"}",regx)
		print("[+] Description:",x.group(1))

		#Date
		x = re.search("\"published\":\"(.*?)T",regx)
		print("[+] Published Date (Y/M/D):",x.group(1))

		#Base Score
		x = re.search("\"baseScore\":(.*?),\"baseSeverity\":\"(.*?)\"",regx)
		print("[+] Base Score:",x.group(1),x.group(2))

		#Attack Vector & Complexity
		x = re.search("\"attackVector\":\"(.*?)\",\"attackComplexity\":\"(.*?)\",",regx)
		print("[+] Attack Vector:",x.group(1))
		print("[+] Attack Complexity:",x.group(2))		

		print(border)


def retire_js_cve(file):
	cve_arr = []
	try:
		with open(file) as openfileobj:
			for line in openfileobj:
				cve = re.findall("CVE-....-.....?",line)
				if cve != None:
					cve_arr.append(cve)

		cve_uniq = []
		for item in cve_arr:
			if item not in cve_uniq:
				cve_uniq.append(item)

		cve_uniq_2 = []

		for item in cve_uniq:
			if item not in cve_uniq_2:
				cve_uniq_2.append(item)


		print("[+] List of found CVE-s:",cve_uniq_2)
		for i in cve_uniq_2:
			get_cve_data(str(i).strip("[']"))

	except IOError as e:
		print(str(e))

def main():

	if args.r:
		retire_js_cve(str(sys.argv[2]))
	
	if args.c:
		get_cve_data(str(sys.argv[2]))


if __name__=="__main__":
	main()
