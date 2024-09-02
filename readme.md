# CriminalIPSploit :globe_with_meridians: ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

***CriminalIPSploit*** is a specialized tool designed for querying vulnerability information using the CriminalIP API. It retrieves details on *IP vulnerabilities*, *IPs linked to domains*, and *comprehensive vulnerability data*.

If you are rather looking for a simpler quick mass scan on whether the IP is safe or not, you can check my previous [mass IP scanner](https://github.com/leeheehee4/Mass_CriminalIp_Scanner). 🔎

  

## Prerequisites 🔓

  

You need Criminal IP API Key from criminalip.io 🔑

> [!NOTE]
> I personally use this a lot because I'm using paid subscription 💀
> but for API Key itself, you can get them for FREE on its [website](https://criminalip.io/) straight away

  

## Installation 🔓
```
$ git clone https://github.com/{user_name}/CriminalIPSploit.git
$ cd CriminalIPSploit
$ pip install -r requirements.txt
```
## Where to add API Key 🔓

  

1️⃣ Put it in `api_key.txt` like this, *or*

![api_key text file](image-2024-8-23_11-23-13.png)

2️⃣ type it directly in the **Terminal** !

![terminal](image-2024-8-23_11-24-46.png)

  

## Run
 Run the attached python script!
```
$ python criminalipsploit.py
```
## Tools List

```
########## Main ########## 
[1] Account Info 
[2] Change API Key 
[3] Search IP Vulnerability Info 
[4] Search Domain Connected IPs 
[5] Exploit Search 

########### Exploit Search ########## 
[1] [GET] /v1/exploit/author 
[2] [GET] /v1/exploit/cve_id 
[3] [GET] /v1/exploit/edb_id 
[4] [GET] /v1/exploit/platform 
[5] [GET] /v1/exploit/type 
[6] [GET] /v1/exploit/verified 
[7] [GET] /v1/exploit/year [8]

[GET] /v1/exploit/{user_input_filters}
```

## Example Images 📝

  

![example1](image-2024-8-23_11-36-17.png)

![example2](image-2024-8-23_11-37-6.png)

![example3](image-2024-8-23_11-37-46.png)