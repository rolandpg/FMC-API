# python 3.9.7 64-bit
# author Patrick Roland
# using VS Code, Win 10
# encoding utf-8

# this code will count access rule hits where logging is enabled on a per-firewall basis
# and return a CSV file of unused rule to aid in the cleanup of firewall rules.

# Some variables redacted for security purposes

import requests
import json
import time
import logging
from collections import defaultdict
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.basicConfig(filename='response.log',level=logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.INFO)
requests_log.propagate = True

deviceUuidList = {
    "":"",
    "":"",
    
}  #dictionary of UUID for your FTD firewalls <hostname:UUID>

domainUUID = "" # Domain UUID
accessPolicyUUID = "" # Access USDCEDGFW

fmcUrl = "" #url of Firepower management center

user1= input("Enter your FMC username: ")
pass1= input("Enter your FMC password: ")

querystring = {"limit":"1000"}
#API query Filter


#inital authentication header
headers = {
    'cache-control': "no-cache",
    'postman-token': ""
    }

url = "%s/api/fmc_platform/v1/auth/generatetoken" % fmcUrl

response = requests.request("POST", url, headers=headers, auth=(user1,pass1), verify=False)

# Authenicates token used in addiotnal HTTPS CRUD request
auth = response.headers['X-auth-access-token']
authRefresh = response.headers['X-auth-refresh-token']

headers = {
    'x-auth-access-token': auth,
    'cache-control': "no-cache",
    'postman-token': "",
    'expanded':'true'
    }

reAuthHeaders = {
    'x-auth-access-token': auth,
    'X-auth-refresh-token': authRefresh,
    'cache-control': "no-cache",
    'postman-token': "",
    'expanded':'true'
    }

def reauthenication():
    url = "%s/api/fmc_platform/v1/auth/generatetoken" % fmcUrl
    response = requests.request("POST", url, headers=reAuthHeaders, auth=(user1,pass1), verify=False)
    auth = response.headers['X-auth-access-token']
    authRefresh = response.headers['X-auth-refresh-token']

def updateHits():
    #update hit counters for Access rules
    for device in deviceUuidList.values():
        querFilt = "filter=%22deviceId%3A{}".format(device)
        url = "{}/api/fmc_config/v1/domain/{}/policy/accesspolicies/{}/operational/hitcounts?{}".format(fmcUrl,domainUUID,accessPolicyUUID,querFilt)
        requests.request("PUT",url,headers=headers, verify=False)
        time.sleep(0.5)

def Nohitcounter(firewallname):
    qFilter = "filter=%22deviceId%3A{}%3BfetchZeroHitCount%3Atrue%22&limit=1000&expanded=true".format(deviceUuidList[firewallname])
    #Count Rules with No Hits
    url = "{}/api/fmc_config/v1/domain/{}/policy/accesspolicies/{}/operational/hitcounts?{}".format(fmcUrl,domainUUID,accessPolicyUUID,qFilter)
    noHits = requests.request("GET", url, headers=headers, verify=False)
    nH = noHits.json()
	#write a json file of the access rules
    with open('NoHits.json', 'w') as output:
        output.write(json.dumps(nH, sort_keys=True, indent=4))
    with open('ZeroHits_{}.csv'.format(firewallname), 'w') as file:
        file.write("Name,UUID\n")
    try:
        for rule in nH['items']:
            url = "{}/api/fmc_config/v1/domain/{}/policy/accesspolicies/{}/accessrules/{}?".format(fmcUrl,domainUUID,accessPolicyUUID,rule['rule']['id'])
            logSetting = requests.request("GET", url, headers=headers, verify=False)
            logRespJson = logSetting.json()
            logResp = logRespJson['enableSyslog']
            #print(rule['rule']['name'] +'\n'+ logResp +'\n')
            time.sleep(0.5)
            if logResp:
                with open('ZeroHits_{}.csv'.format(firewallname), 'a') as file:
                    file.write(rule['rule']['name'] + ',' + rule['rule']['id']+'\n')
            else:
                pass
    except KeyError:
        print("Key-error\n")
        

updateHits()
#reauthenication()

Nohitcounter('')# pass your firewall name
Nohitcounter('')# pass another firewall name
