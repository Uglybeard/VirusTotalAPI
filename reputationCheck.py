import requests
import json
import re
from urllib.parse import urlparse

files = []
domains=[]
errors=[]
ips=[]
malicious=[]

hash_regex = r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$"
domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
url_regex = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$"

headers = {
    "accept": "application/json",
    "x-apikey": "<API_KEY>" #REPLACE <API_KEY> with your API Key
}

def remove_ip_port(ip):
    if ":" in ip:
        splitted_ip = ip.split(":")
        return splitted_ip[0]
    return ip

def domain_parse(inp):
  inp=inp.replace("[","").replace("]","").replace("hxxps","https").replace("hxxp","http").replace(" ","")
  splitted_inp=inp.split("//")
  if splitted_inp[0] not in ("https:","http:","hxxp:","hxxps:"):
    inp="https://" + inp
  if "." not in inp: return -1

  inp_parsed=urlparse(inp).netloc
  if inp_parsed=="":
    print("Problem parsing the following domain:" + inp)
    return inp
  else:
    return inp_parsed

def hash_check(file):
    url = "https://www.virustotal.com/api/v3/files/" + file
    
    response = requests.get(url, headers=headers)
    f.write("Results for " + file + ": \n")

    if response.status_code==200:
        data = response.json()

        last_analysis_results = data["data"]["attributes"]["last_analysis_results"]
        cont=0
        for engine, result in last_analysis_results.items():
            category = result["category"]
            if category not in ("undetected","type-unsupported","timeout","confirmed-timeout","failure"):
                f.write(f"{engine}: {category}\n")
                if (file not in malicious): malicious.append(file)
                cont+=1
        if cont==0:
            f.write("Undetected\n")
    else: 
        f.write("File not found\n")
    f.write("\r")

def domain_check(domain):
    url = "https://www.virustotal.com/api/v3/domains/" + domain

    response = requests.get(url, headers=headers)
    f.write("Results for " + domain + ": \n")
    cont=0
    
    if response.status_code==200:
        data = response.json()

        if "data" in data:
            last_analysis_results = data["data"]["attributes"]["last_analysis_results"]
            for engine, result in last_analysis_results.items():
                category = result["category"]
                if category not in ("harmless","undetected"): 
                    f.write(f"{engine}: {category}\n")
                    if (domain not in malicious): malicious.append(domain)
                    cont+=1
            if cont==0:
                f.write("Undetected\n")
    else:
        f.write("Domain not found\n")
    f.write("\r")

def ip_check(ip):
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
    response = requests.get(url, headers=headers)
    f.write("Results for " + ip + ": \n")
    cont=0

    if response.status_code==200:
        data = response.json()

        if "data" in data:
            last_analysis_results = data["data"]["attributes"]["last_analysis_results"]
            for engine, result in last_analysis_results.items():
                category = result["category"]
                if category not in ("harmless","undetected"): 
                    f.write(f"{engine}: {category}\n")
                    if (ip not in malicious): malicious.append(ip)
                    cont+=1
            if cont==0:
                f.write("Undetected\n")
    else:
        f.write("IP address not found\n")
    f.write("\r")

try:
    print("Enter input (or 'q' to quit):")
    while True:
        inp = input()
        if inp.lower() == 'q':
            break

        if re.match(hash_regex,inp): files.append(inp)
        elif re.match(domain_regex,inp): domains.append(inp)
        elif re.match(url_regex,inp):
            result=domain_parse(inp)
            if re.match(domain_regex,result): domains.append(result)
            elif re.match(ip_regex,result): ips.append(result)
            else: errors.append(inp)
        elif re.match(ip_regex,inp): 
            inp = remove_ip_port(inp)
            ips.append(inp)   
        else: errors.append(inp)

except Exception as e:
    print("Error:", e)

with open("VT_ReputationCheck.txt", "w") as f:
    if(len(files)!=0):
        f.write("----------- FILES -----------\n")
        for file in files:
            hash_check(file)

    if(len(domains)!=0):
        f.write("--------- DOMAINS ---------\n")
        for domain in domains:
            domain_check(domain)

    if(len(ips)!=0):
        f.write("--------- IP ADDRESSES ---------\n")
        for ip in ips:
            ip_check(ip)

    if(len(malicious)!=0):
        f.write("--------- SUSPECT/MALICIOUS SUMMARY ---------\n")
        for obj in malicious:
            f.write(obj + "\n")

    if(len(errors)!=0):
        f.write("--------- UNKNOWN CATEGORY, NOT ANALYZED ---------\n")
        for error in errors:
            f.write(error + "\n")
