# CVEcrystalyer

CVE tool to help with getting CVE details needed for reporting. Tool uses reitre-js.html as input, it will parse all of the CVE-s and grab the details from NVD and print them in terminal for copy/paste.

```bash
./CVEcrystalyer -h                      
    -c NAME                          Single CVE | Multiple CVE-s separated with ',' -> -c CVE-XXX-XXXX,CVE-XXX-XXXX,CVE-XXX-XXXX
    -r PATH                          Get CVE-s from Retire_JS.html output
    -h, --help                       e.g. ./CVEcrystalyer -r retire_js.html | ./CVEcrystalyer -c CVE-2020-11022

```
*preview*
```bsh
["CVE-2021-23357", "CVE-2021-23358"]
[+] Current CVE -> CVE-2021-23357
**************************************************
Description: All versions of package github.com/tyktechnologies/tyk/gateway are vulnerable to Directory Traversal via the handleAddOrUpdateApi function. This function is able to delete arbitrary JSON files on the disk where Tyk is running via the management API. The APIID is provided by the user and this value is then used to create a file on disk. If there is a file found with the same name then it will be deleted and then re-created with the contents of the API creation request.
Published Date (Y/M/D): 2021-03-15
Base Score: 5.3
Base Severity: MEDIUM
Attack Vector: LOCAL
Attack Complexity LOW
**************************************************
[+] Current CVE -> CVE-2021-23358
**************************************************
Description: The package underscore from 1.13.0-0 and before 1.13.0-2, from 1.3.2 and before 1.12.1 are vulnerable to Arbitrary Code Injection via the template function, particularly when a variable property is passed as an argument as it is not sanitized.
Published Date (Y/M/D): 2021-03-29
Base Score: 7.2
Base Severity: HIGH
Attack Vector: NETWORK
Attack Complexity LOW
**************************************************
```


## Installation
This tool is writen in Crystal lang, so if you want to compile your own binary please first install Crystal lang and compile it. I will be uploading binaries for different systems so ping me if there is no binary for you system.


## Roadmap
TODO -> add config.json where you can add which items you want to search for
