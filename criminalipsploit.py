#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests as req
import json
import os
import time
from prettytable import PrettyTable, ALL

base_url = "https://api.criminalip.io"

logo_txt = """
 ██████╗██████╗ ██╗███╗   ███╗██╗███╗   ██╗ █████╗ ██╗     ██╗██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔════╝██╔══██╗██║████╗ ████║██║████╗  ██║██╔══██╗██║     ██║██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██║     ██████╔╝██║██╔████╔██║██║██╔██╗ ██║███████║██║     ██║██████╔╝███████╗██████╔╝██║     ██║   ██║██║   ██║   
██║     ██╔══██╗██║██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║     ██║██╔═══╝ ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   
╚██████╗██║  ██║██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗██║██║     ███████║██║     ███████╗╚██████╔╝██║   ██║   
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝"""

main_description = """
[Description]
Criminalsploit is a CLI tool for retrieving CriminalIP search results, especially for Exploit Search.
You can save the results as a file.
"""

main_menu_txt = """
 [1] Account Info
 [2] Change API Key
 [3] Search IP Vulnerability Info
 [4] Search Domain Connected IPs
 [5] Exploit Search

 [0] Exit
"""

exploit_api_description = """
[API Description]
API for retrieving information on a specific CVE vulnerability."""

exploit_menu_txt = """
 [1] [GET] /v1/exploit/author
 [2] [GET] /v1/exploit/cve_id
 [3] [GET] /v1/exploit/edb_id
 [4] [GET] /v1/exploit/platform
 [5] [GET] /v1/exploit/type
 [6] [GET] /v1/exploit/verified
 [7] [GET] /v1/exploit/year
 [8] [GET] /v1/exploit/{user_input_filters}
 
 [0] Back
"""

def get_api_key():
    try:
        with open('./api_key.txt', 'r', encoding='utf-8') as f:
            api_key = f.readline().strip()
        if not (is_valid_api_key(api_key)):
            while True:
                api_key = new_api_key()
                if(api_key):
                    break
    except Exception as e:
        print("\033[31m"+"\n[Error] Function : get_api_key()\n"+"\033[0m", e)
        api_key = new_api_key()
    return api_key

def new_api_key():
    try:
        while True:
            api_key = input("\n[*] Please enter your CriminalIP API key : ")
            if(is_valid_api_key(api_key)):
                break
        with open('./api_key.txt', 'w', encoding='utf-8') as f:
            f.write(api_key)
        return api_key
    except Exception as e:
        print("\033[31m"+"\n[Error] Function : new_api_key()\n"+"\033[0m", e)
    return

def get_account_info(user_api_key):
    url = base_url + "/v1/user/me"
    api_header = {"x-api-key": user_api_key}
    res = req.post(url, headers=api_header)
    return res.json()

def is_valid_api_key(api_key):
    print("[*] Validating your API key. Please wait...")
    status_code = get_account_info(api_key)['status']
    if status_code == 200:
        print("[*] Your API key has been validated.")
        return True
    else:
        print("\033[31m"+"\n[Error] Invalid API Key\n"+"\033[0m")
        return False

def main(api_key):
    while True:
        print(main_menu_txt)
        o = input("Option number : ")
        if o == "0":
            print("[*] Terminating...\n")
            exit()
        elif o == '1':
            account_info = get_account_info(api_key)
            print("\n#################### Response ####################")
            print(json.dumps(account_info, indent=4, sort_keys=True))
            pause()
        elif o == '2':
            try:
                api_key = new_api_key()
            except KeyboardInterrupt:
                print("\n[*] Canceled\n")
                pause()
        elif o == '3':
            result = search_ip_vuln_info()
            if(result):
                save_result_as_file(result)
                del result
            pause()
        elif o == '4':
            result = search_domain_connected_ip()
            if(result):
                save_result_as_file(result)
                del result
            pause()
        elif o == '5':
            exploit_search()
        else:
            print("\033[31m"+"\n[Error] Not a valid option\n"+"\033[0m")
            pause()

def search_ip_vuln_info():
    try:
        ip = input("\nIP : ")
        url = base_url + "/v1/asset/ip/report"
        api_header = {"x-api-key": api_key}
        params = {"ip": ip, "full": "true"}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            vuln_info_list = res_json["vulnerability"]["data"]

            if(len(vuln_info_list) > 0):
                table = PrettyTable(hrules=ALL)
                table.field_names = ["CVE-ID", "Application", "EDB-ID", "Type", "Description"]
                table._max_width = {"CVE-ID": 20, "Application": 20, "EDB-ID": 10, "Type": 20, "Description": 100}
                for vuln_info in vuln_info_list:
                    cve_id = str(vuln_info["cve_id"])
                    cve_description = str(vuln_info["cve_description"])
                    list_edb = vuln_info["list_edb"]
                    if(len(list_edb) > 0):
                        edb_id = [str(edb['edb_id']) for edb in list_edb]
                        edb_id = "\n".join(edb_id)
                    else:
                        edb_id = ""
                    app = vuln_info["app_name"]+" "+vuln_info["app_version"]
                    type = vuln_info["type"]
                    table.add_row([cve_id, app, edb_id, type, cve_description])
                print(table)
                return table
            else:
                print("\n[*] No vulnerabilties are found.\n")
                return
        else:
            api_error(res_json, "/v1/asset/ip/report")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
    except Exception as e:
        print("\033[31m"+"\n[Error] Function : search_ip_vuln_info()\n"+"\033[0m", e)
    return   

def search_domain_connected_ip():
    try:
        domain = input("\nDomain : ")
        scan_id = get_domain_scan_id(domain)
        if(scan_id):
            api_header = {"x-api-key": api_key}
            url = base_url + "/v2/domain/report/"+str(scan_id)
            res = req.get(url, headers=api_header)
            res_json = res.json()
            if(res_json["status"]==200):
                connected_ip_list = res_json["data"]["connected_ip"]
                if(len(connected_ip_list) > 0):
                    table = PrettyTable(hrules=ALL)
                    table.field_names = ["IP", "Score"]
                    table._max_width = {"IP": 20, "Score": 20}
                    for connected_ip in connected_ip_list:
                        ip = connected_ip["ip"]
                        score = connected_ip["score"]
                        table.add_row([ip, score])
                    print(table)
                    return table
                else:
                    print("\n[*] No connected IPs are found.\n")
            else:
                api_error(res_json, "/v2/domain/report/{id}")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
    except Exception as e:
        print("\033[31m"+"[Error] Function : serach_domain_connected_ip()\n"+"\033[0m", e)
    return

def get_domain_scan_id(domain):
    try:
        url = base_url + "/v1/domain/reports"
        api_header = {"x-api-key": api_key}
        params = {"query": domain}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            reports = res_json["data"]["reports"]
            if(len(reports) > 0):
                return reports[0]["scan_id"]
            else:
                print("\n[*] No Scan ID is Found.")
                scan = input("\n[*] Do you want to start a new scan? (y/n)\n")
                if(scan=="y" or scan=="Y"):
                    scan_id = get_new_domain_scan_id(domain)
                    if(scan_id):
                        return scan_id
        else:
            api_error(res_json, "/v1/domain/reports")
    except Exception as e:
        print("\033[31m"+"[Error] Function : get_domain_scan_id\n"+"\033[0m", e)
    return

def get_new_domain_scan_id(domain):
    try:
        url = base_url + "/v1/domain/scan"
        api_header = {"x-api-key": api_key}
        data = {"query": domain}
        res = req.post(url, headers=api_header, data=data)
        res_json = res.json()
        if(res_json["status"]==200):
            scan_id = res_json["data"]["scan_id"]
            while True:
                percentage = get_domain_scan_status(scan_id)
                if(percentage == -1):
                    print("\033[31m"+"\n[Error] Scan Failed.\n"+"\033[0m")
                    break
                elif(percentage == -2):
                    print("\033[31m"+"\n[Error] Domain does not exist.\n"+"\033[0m")
                    break
                else:
                    print(f"[*] Scan Status : {percentage}%")
                    if(percentage == 100):
                        return scan_id
                    time.sleep(3)
        else:
            api_error(res_json, "/v1/domain/scan")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
    except Exception as e:
        print("\033[31m"+"[Error] Function : get_new_domain_scan_id\n"+"\033[0m", e)
    return

def get_domain_scan_status(scan_id):
    try:
        url = base_url + "/v1/domain/status/" + str(scan_id)
        api_header = {"x-api-key": api_key}
        res = req.get(url, headers=api_header)
        res_json = res.json()
        if(res_json["status"]==200):
            return res_json["data"]["scan_percentage"]
        else:
            api_error(res_json, "/v1/domain/status/{id}")
    except Exception as e:
        print("\033[31m"+"[Error] Function : get_domain_scan_status\n"+"\033[0m", e)
    return

def exploit_search():
    while True:
        print(exploit_api_description)
        print(exploit_menu_txt)
        o = input("Option number : ")
        if o == '0':
            return
        elif o == '1':
            result = exploit_author()
        elif o == '2':
            result = exploit_cve_id()
        elif o == '3':
            result = exploit_edb_id()
        elif o == '4':
            result = exploit_platform()
        elif o == '5':
            result = exploit_type()
        elif o == '6':
            result = exploit_verified()
        elif o == '7':
            result = exploit_year()
        elif o == '8':
            result = exploit_user_input_filters()
        else:
            print("\033[31m"+"\n[Error] Not a valid option\n"+"\033[0m")
        try:
            if(result):
                save_result_as_file(result)
                del(result)
        except:
            pass
        pause()

def exploit_author():
    description = """
[Filter Description]
Author : Returns results of the author. Case sensitivity is required.
Example) author: AntiSecurity
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("Author : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "author:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_author()\n"+"\033[0m", e)
        pause()
    return

def exploit_cve_id():
    description = """
[Filter Description]
cve_id : Returns the result of the CVE ID.
Example) cve_id: CVE-2019-20800
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("CVE-ID : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "cve_id:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_cve_id()\n"+"\033[0m", e)
        pause()
    return

def exploit_edb_id():
    description = """
[Filter Description]
edb_id : Returns the result corresponding to the EDB-ID of the Exploit DB.
Example) edb_id: 43134
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("EDB-ID : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "edb_id:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_edb_id()\n"+"\033[0m", e)
        pause()
    return

def exploit_platform():
    description = """
[Filter Description]
platform : Returns the result of the application platform.
Example) platform: PHP
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("Platform : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "platform:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_platform()\n"+"\033[0m", e)
        pause()
    return

def exploit_type():
    description = """
[Filter Description]
type : Returns the result of the application type.
Example) type: WEBAPPS
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("Type : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "type:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_type()\n"+"\033[0m", e)
        pause()
    return

def exploit_verified():
    description = """
[Filter Description]
verified : 
Returns the result of whether Exploit DB has validated it.
Example) verified: verified / verified: unverified
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("Verified : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "verified:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_verified()\n"+"\033[0m", e)
        pause()
    return

def exploit_year():
    description = """
[Filter Description]
year : Returns the results of the year.
Example) year: 2021
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("Year : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": "year:"+query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"[Error] Function : exploit_year()\n"+"\033[0m", e)
        pause()
    return

def exploit_user_input_filters():
    description = """
[Filter List]
  author : Returns results of the author. Case sensitivity is required.
  cve_id : Returns the result of the CVE ID.
  edb_id : Returns the result corresponding to the EDB-ID of the Exploit DB.
platform : Returns the result of the application platform.
    type : Returns the result of the application type.
verified : Returns the result of whether Exploit DB has validated it.
    year : Returns the results of the year.
     " " : Please use a double quote to separate banner search terms from the filter values.

You can also use 'AND', 'NOT', and 'OR' operators.
Example) author:AntiSecurity NOT cve_id:CVE-2010-2033
"""
    print(description)
    url = base_url + "/v1/exploit/search"
    try:
        query = input("Query : ")
        offset = input("Offset : ")
        api_header = {"x-api-key": api_key}
        params = {"query": query, "offset": offset}
        res = req.get(url, headers=api_header, params=params)
        res_json = res.json()
        if(res_json["status"]==200):
            return print_exploit_search_result(res_json)
        else:
            api_error(res_json, "/v1/exploit/search")
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
        pause()
    except Exception as e:
        print("\033[31m"+"\n[Error] Function : exploit_user_input_filters()\n"+"\033[0m", e)
        pause()
    return

def print_exploit_search_result(res_json):
    try:
        table = PrettyTable(hrules=ALL)
        table.field_names = ["Author", "CVE-ID", "EDB-ID", "Registered Date", "Platform", "title", "type", "Verification"]
        table._max_width = {"Author": 20, "CVE-ID": 20, "EDB-ID": 20, "Year": 20, "title": 100, "type": 20, "Verification": 20}
        result_list = res_json["data"]["result"]
        if(len(result_list) > 0):
            for result in result_list:
                author = result["author"]
                cve_ids = result["cve_id"]
                cve_ids = "\n".join(cve_ids)
                edb_id = result["edb_id"]
                year = result["edb_reg_date"]
                platform = result["platform"]
                title = result["title"]
                type = result["type"]
                verify_code = result["verify_code"]
                table.add_row([author, cve_ids, edb_id, year, platform, title, type, verify_code])
            print(table)
            return table
        else:
            print("\n[*] No Results are found\n")
    except Exception as e:
        print("\033[31m"+"\n[Error] Function : print_exploit_search_result()\n"+"\033[0m", e)
        pause()
    return

def save_result_as_file(result):
    try:
        save=input("\nDo you want to save the search result as a file? (y/n)\n")
        if(save=='y' or save=='Y'):
            print("[*] Your file will be saved in \'./saved_response/\'.\n")
            filename = input("Filename : ")
            if not (os.path.isdir("./saved_response")):
                os.makedirs("./saved_response")
            with open("./saved_response/"+filename, "w", encoding="utf-8") as f:
                f.write(str(result))
            print("\n[*] File Saved.\n")
        
    except KeyboardInterrupt:
        print("\n[*] Canceled\n")
    except Exception as e:
        print("\033[31m"+"\n[Error] Function : save_result_as_file()\n"+"\033[0m", e)

def pause():
    input("\nPress any key to continue...")

def api_error(res_json, api):
    print("\033[31m"+"\n[Error] API Error "+api+"\n"+"\033[0m")
    status = res_json["status"]
    msg = res_json["message"]
    print(f"Status Code : {status}\nMessage : {msg}")

if __name__ == "__main__":
    print(logo_txt)
    print(main_description)
    api_key = get_api_key()
    pause()
    main(api_key)