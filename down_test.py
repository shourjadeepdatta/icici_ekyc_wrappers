import requests
import json

url = "https://api-dev.test.getkwikid.com/kyc/ekyc_download"

payload = json.dumps({
  "APP_PAN_NO": "BAMPM9343K",
  "APP_PAN_DOB": "25-05-1975",
  "APP_POS_CODE": "L",
  "APP_OTHKRA_CODE": "THINKEKYC",
  "APP_OTHKRA_BATCH": "TEST 22-05-2017",
  "APP_IOP_FLG": "IE",
  "APP_REQ_DATE": "skjndkjd",
  "APP_TOTAL_REC": "1"
})
headers = {
  'accept': '*/*',
  'accept-language': 'en-US,en;q=0.9',
  'access-control-request-headers': 'content-type',
  'access-control-request-method': 'POST',
  'cache-control': 'no-cache',
  'origin': 'https://app-dev.test.getkwikid.com',
  'pragma': 'no-cache',
  'priority': 'u=1, i',
  'referer': 'https://app-dev.test.getkwikid.com/',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-site',
  'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
  'content-type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)

