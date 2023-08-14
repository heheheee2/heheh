import tls_client, threading, os, requests
from base64 import b64encode
import json, time, os
import fade
from colorama import Fore

__useragent__ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"  #requests.get('https://discord-user-api.cf/api/v1/properties/web').json()['chrome_user_agent']
build_number = 165486  #int(requests.get('https://discord-user-api.cf/api/v1/properties/web').json()['client_build_number'])
cv = "108.0.0.0"
__properties__ = b64encode(
  json.dumps(
    {
      "os": "Windows",
      "browser": "Chrome",
      "device": "PC",
      "system_locale": "en-GB",
      "browser_user_agent": __useragent__,
      "browser_version": cv,
      "os_version": "10",
      "referrer": "https://discord.com/channels/@me",
      "referring_domain": "discord.com",
      "referrer_current": "",
      "referring_domain_current": "",
      "release_channel": "stable",
      "client_build_number": build_number,
      "client_event_source": None
    },
    separators=(',', ':')).encode()).decode()


def get_headers(token):
  headers = {
    "Authorization": token,
    "Origin": "https://canary.discord.com",
    "Accept": "*/*",
    "X-Discord-Locale": "en-GB",
    "X-Super-Properties": __properties__,
    "User-Agent": __useragent__,
    "Referer": "https://canary.discord.com/channels/@me",
    "X-Debug-Options": "bugReporterEnabled",
    "Content-Type": "application/json"
  }
  return headers
os.system("cls" if os.name == "nt" else "clear")

BoostBot = f"""  _                     _       _           _                                                             
 | |_    ___     ___   | |     (_)   ___   (_)  _ __      ___    ___   _ __  __   __   ___   _   _   _ __ 
 | __|  / _ \   / _ \  | |     | |  / _ \  | | | '_ \    / __|  / _ \ | '__| \ \ / /  / _ \ | | | | | '__|
 | |_  | (_) | | (_) | | |     | | | (_) | | | | | | |   \__ \ |  __/ | |     \ V /  |  __/ | |_| | | |   
  \__|  \___/   \___/  |_|    _/ |  \___/  |_| |_| |_|   |___/  \___| |_|      \_/    \___|  \__,_| |_|   
                             |__/                                                                         """
Account =f"""		{Fore.GREEN}Legit Market"""
fade_text = fade.pinkred(BoostBot)
print(fade_text+'\n'+Account+'\n')

config = json.load(open("config.json", encoding="utf-8"))
tkn = config.get("bot_token")
secret = config.get("secret")
client_id = config.get("client_id")
redirect = config.get("redirect")
API_ENDPOINT = 'https://canary.discord.com/api/v9'
auth = f"https://canary.discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect}&response_type=code&scope=identify%20guilds.join"
guild = input(f"{Fore.GREEN}[ ~ ] {Fore.GREEN}ID du serveur pour faire rejoindre le serveur: ")

def exchange_code(code):
  data = {
    'client_id': client_id,
    'client_secret': secret,
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': redirect
  }
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  r = requests.post(str(API_ENDPOINT) + '/oauth2/token', data=data, headers=headers)
  print(r.text)
#   print(r.status_code)
  if r.status_code in (200, 201, 204):
    return r.json()
  else:
    return False

def add_to_guild(access_token, userID):
  url = f"{API_ENDPOINT}/guilds/{guild}/members/{userID}"

  botToken = tkn
  data = {
    "access_token": access_token,
  }
  headers = {
    "Authorization": f"Bot {botToken}",
    'Content-Type': 'application/json'
  }
  r = requests.put(url=url, headers=headers, json=data)

  return r.status_code

def authorizer(tk):
    headers = get_headers(tk)
    r = requests.post(auth, headers=headers, json={"authorize": "true"})
    print(r.text)
    if r.status_code in (200, 201, 204):
        
        location = r.json()['location']
        
        code = location.replace("http://localhost:8080?code=", "")
        
        exchange = exchange_code(code)
        print(f"{Fore.LIGHTGREEN_EX}[ + ] {Fore.WHITE}Token Autorisée")
        access_token = exchange['access_token']
        userid = get_user(access_token)
        add_to_guild(access_token, userid)
        print(f"{Fore.LIGHTGREEN_EX}[ + ] {Fore.WHITE}Ajouter au serveur%s" % (guild))
        return "ok"

   
def get_user(access: str):
  endp = "https://canary.discord.com/api/v9/users/@me"
  r = requests.get(endp, headers={"Authorization": f"Bearer {access}"})
  rjson = r.json()
  return rjson['id']

def main(tk):
    authorizer(tk)
    headers = get_headers(tk)
    client = tls_client.Session(client_identifier="firefox_102")
    client.headers.update(headers)
    

f = open("tokens.txt", "r").readlines()

os.system("cls" if os.name == "nt" else "clear")
for tk in f:
    tk = tk.strip()
    tk = tk.split(":")[2]
    threading.Thread(target=main, args=(tk,)).start()