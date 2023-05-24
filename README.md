# VirusTotalAPI - Check IP, domain and file reputation

## Check IP, domain and file reputation

Enter a list of IP addresses, URLs, domains, SHA1, SHA256 or MD5 divided by a new-line (press enter) to get their reputation as a result.

Once started, the script will prompt you to enter the above entries or "q" to end execution.

You can enter many different entries at once, so there is no need to divide them by type (for example, you can analyze SHA256 and URL together). 

When the analysis is complete, a ".txt" file named "VT_ReputationCheck.txt" will be generated containing the result of the analysis performed on all the entries entered.

The result will be broken down by type, reporting the following entries: Domains, IP Addresses, Files, Suspicious/Malicious Summary and Unknown.

- Domains: contains the report of security vendors that have identified individual domains and/or Urls as malicious.
- IP Addresses: contains the summary of security vendors that identified individual IP addresses as malicious.
- FIles: contains the report of security vendors that identified individual SHA1, SHA256 and/or MD5 as malicious.
- Suspicious/Malicious Summary: contains the summary of all domains, IP addresses, and files that were deemed malicious.
- Unknown: contains the entries that the code was unable to identify and, consequently, analyze

The report of each individual file will contain the security vendors that flagged it as malicious or suspicious, "Undetected" in case it is clean or "Not found" in case it is not on the VirusTotal database.

## Execution example

_Remember to replace <API_KEY> with the actual API key within the code._

Following is an example of code execution:

`python3 reputationCheck.py`

Input:

```
Enter input (or 'q' to quit):
google.com
https://127.0.0.1
eb5e57e7db3af792b4c9e9f28525843b
1EE3D7C80D075D64F97D04D036E558043F2F6BC959C87CD5B0A6D53B96B96A0F
192.168.1.1
1.2.3.4
abcd 
q
```

Output (contents of the file "VT_ReputationCheck.txt"):

```
----------- FILES -----------
Results for eb5e57e7db3af792b4c9e9f28525843b: 
Lionic: malicious
MicroWorld-eScan: malicious
ClamAV: malicious
CAT-QuickHeal: malicious
ALYac: malicious
Sangfor: malicious
Alibaba: malicious
VirIT: malicious
Cyren: malicious
Symantec: malicious
ESET-NOD32: malicious
Avast: malicious
Cynet: malicious
Kaspersky: malicious
BitDefender: malicious
NANO-Antivirus: malicious
Tencent: malicious
Emsisoft: malicious
F-Secure: malicious
VIPRE: malicious
McAfee-GW-Edition: malicious
FireEye: malicious
Sophos: malicious
GData: malicious
Avira: malicious
Antiy-AVL: malicious
Microsoft: malicious
Arcabit: malicious
ZoneAlarm: malicious
Google: malicious
AhnLab-V3: malicious
MAX: malicious
Zoner: malicious
Rising: malicious
Fortinet: malicious
AVG: malicious

Results for 1EE3D7C80D075D64F97D04D036E558043F2F6BC959C87CD5B0A6D53B96B96A0F: 
Undetected

--------- DOMAINS ---------
Results for google.com: 
Undetected

--------- IP ADDRESSES ---------
Results for 127.0.0.1: 
Undetected

Results for 192.168.1.1: 
Undetected

Results for 1.2.3.4: 
CRDF: malicious
CyRadar: malicious
Sucuri SiteCheck: malicious
CrowdSec: suspicious

--------- SUSPECT/MALICIOUS SUMMARY ---------
eb5e57e7db3af792b4c9e9f28525843b
1.2.3.4

--------- UNKNOWN CATEGORY, NOT ANALYZED ---------
abcd
```














