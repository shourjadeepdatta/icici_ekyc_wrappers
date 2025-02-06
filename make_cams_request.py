import requests
from urllib.parse import urlencode
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import xmltodict
import base64

from dicttoxml import dicttoxml
from xml.dom.minidom import parseString

from pdf2image import convert_from_path
from config import pol_mapper, tin_mapper, country_mapper
import boto3
from boto3.dynamodb.conditions import Key
#from helpers import encrypt_payload

dynamo = boto3.resource('dynamodb',
        region_name='ap-south-1',
        endpoint_url="http://scylla.prod.getkwikid.com:8001/",
        verify=False,
        aws_access_key_id='KIA2YVUKFCK6XQW6KGD',
        aws_secret_access_key='b3lF6qn3lmMJs+1/xZtcvB8NNRMTbMY89wU+CHyu')

def custom_item_func(x):
    # Check if the key starts with '@', which indicates it should be an element itself
    if isinstance(x, tuple) and len(x) == 2 and x[0].startswith('@'):
        return x[0][1:], x[1]
    return x

def convert_dict_to_xml(dict_data):
    # Convert the dictionary to an XML byte string
    xml_bytes = dicttoxml(dict_data, root=False, attr_type=False)#, item_func=custom_item_func(dict_data))
    # Convert bytes to a string
    xml_str = xml_bytes.decode()
    # Use minidom to make the output a pretty XML format
    dom = parseString(xml_str)
    return dom.toprettyxml()


state_master = {
	"PUNJAB":"003",
	"HIMACHAL PRADESH":"002",
	"JAMMU AND KASHMIR":"001",
	"CHANDIGARH":"004",
	"UTTARAKHAND":"005",
	"HARYANA":"006",
	"DELHI":"007",
	"RAJASTHAN":"008",
	"UTTAR PRADESH":"009",
	"BIHAR":"010",
	"SIKKIM":"011",
	"ARUNACHAL PRADESH":"012",
	"ASSAM":"013",
	"MANIPUR":"014",
	"MIZORAM":"015",
	"TRIPURA":"016",
	"MEGHALAYA":"017",
	"NAGALAND":"018",
	"WEST BENGAL":"019",
	"JHARKHAND":"020",
	"ODISHA":"021",
	"CHHATTISGARH":"022",
	"MADHYA PRADESH":"023",
	"GUJARAT":"024",
	"DAMAN AND DIU":"025",
	"DADRA AND NAGAR HAVELI":"026",
	"MAHARASHTRA":"027",
	"ANDHRA PRADESH":"028",
	"KARNATAKA":"029",
	"GOA":"030",
	"LAKSHADWEEP":"031",
	"KERALA":"032",
	"TAMIL NADU":"033",
	"PUDUCHERRY":"034",
	"ANDAMAN AND NICOBAR ISLANDS":"035",
	"OTHERS":"099",
	"TELANGANA":"037"
}

title_master = {
	"M":"Mr",
	"F":"Ms",
}

#get_password_url = "https://camskra.com/EIPVAPI/EIPVDetail/Getpassword"
get_password_url = "https://www.camskra.com/EIPVAPI/EIPVDetail/IPVdetailsupd"
#kyc_creation_url = "https://camskra.com/EIPVAPI/EIPVDetail/IPVdetailsupd"
kyc_mod_url = "https://api-dev.test.getkwikid.com/kyc/uat/kra_push"

def convert_bytes_to_base64(data):
    """
    Recursively convert bytes values to base64-encoded strings in a dictionary or list.
    """
    if isinstance(data, dict):
        return {key: convert_bytes_to_base64(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_bytes_to_base64(item) for item in data]
    elif isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')
    return data

def encrypt_payload(payload, key, iv):
    # Convert key and IV from string/base64 to bytes
    key = bytes.fromhex(key)
    iv = base64.b64decode(iv)

    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the payload
    padded_payload = pad(payload.encode('utf-8'), AES.block_size)

    # Encrypt
    encrypted_payload = cipher.encrypt(padded_payload)

    # Encode the result in base64
    return base64.b64encode(encrypted_payload).decode('utf-8')


def decrypt_response(resp,key,iv):
    key = bytes.fromhex(key)
    
    # Decode the IV and encrypted payload from base64
    iv = base64.b64decode(iv)
    encrypted_payload = base64.b64decode(resp)
    
    # Create AES cipher with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the payload
    decrypted_padded_payload = cipher.decrypt(encrypted_payload)
    
    # Unpad the decrypted payload using PKCS7
    decrypted_payload = unpad(decrypted_padded_payload, AES.block_size)
    
    # Convert bytes back to string and return
    return decrypted_payload.decode('utf-8')

def get_base64_from_url(url):
    print("getting base64 for: {}".format(url))
    # Fetch the content from the URL
    response = requests.get(url)
    # Ensure the request was successful
    response.raise_for_status()

    # Get the binary content of the response
    content = response.content

    # Convert the binary content to base64
    base64_encoded_content = base64.b64encode(content)

    # Convert base64 bytes to string
    base64_string = base64_encoded_content.decode('utf-8')

    return base64_string

def get_request_body(req_dict):
	return urlencode(req_dict)
	pass

def get_password():
	payload={'APP_PWD': 'SOURCE$13579',
'APP_PASSKEY': 'LIVE'}
	#payload = {"APP_PWD":"Kras$428242",'APP_PASSKEY': 'UAT'}	
	response = requests.request("POST", get_password_url, data=payload)
	print(response.text)

	pass

def call_cams_kyc_creation_request(request_data,user_id):
	data = convert_bytes_to_base64(request_data)
	key = "ACB5DEBA6E3D86CA8A30BC7C9187FCBA"
	iv = "NmZiYmEzOWFhZjFmZTNhZg=="
	headers = {
	#'Content-Type': 'application/x-www-form-urlencoded',
		# 'x-api-key':'ACB5DEBA6E3D86CA8A30BC7C9187FCB'
		"content-type":"application/json"
	}
	payload = encrypt_payload(json.dumps(data),key,iv)
	pay = {"payload":data}
	with open("{}_reqq.txt".format(user_id),"w") as reqq:
		reqq.write(json.dumps(data))
	#print("reqbody: {}".format(payload))
	try:
		response = requests.request("POST", kyc_mod_url, headers=headers, data=json.dumps(pay))
		print(response.status_code)
		print(response.text)
		with open("{}_respp.txt".format(user_id),"w") as respp:
			respp.write(response.text)
	except Exception as e:
		print("problem while hitting the push api->>",str(e))

	print(response.text)

	with open(request_data.get("APP_PAN")+"_kra_resp.txt","w") as f:
		f.write(response.text)

	kra_response = json.loads(response.text)
	main_resp = kra_response.get("kra_resp","")
	if "KRA009" in main_resp:
		return 0
	#if json.loads(main_resp).get("Response_Code","") != "KRA009":
		#return 1
	else:
		return 1
	#kra_response = decrypt_response(response.text,key,iv)
	#print(kra_response)
	pass

def generate_request_body_from_data(request_raw_data,aadhaar_photo_b64,signature_photo_b64,txnid,nameasperaadhaar,user_id):

	kyc_date = datetime.now().strftime('%d-%b-%Y')
	dob_date = datetime.strptime(request_raw_data["dob"], "%d-%m-%Y").strftime("%d-%b-%Y")
	app_occ = request_raw_data.get("modification_data",{}).get("APP_OCC","")
	if app_occ  == "99":
		app_occupation = ""
	elif app_occ is None:
		app_occupation = ""
	else:
		app_occupation = app_occ
	data = {
		"APP_UPLOAD_TYPE":"03",
		#"APP_USER_ID":"THINKEKYC",
                "APP_USER_ID":"THINKEKYC",#
                "APP_PAN":request_raw_data["pan"],#
		#"APP_PASSWORD":"Sb0j0j0GuBBCgOUVITiJaw==",
                "APP_PASSWORD":"Sb0j0j0GuBBCgOUVITiJaw==",
		#"APP_OTHER_KRA":"THINKEKYC",
                "APP_OTHER_KRA":"THINKEKYC",#
		#"APP_PASSKEY":"UAT",
                "APP_PASSKEY":"UAT",#
                #"APP_POS_CODE":"IBL",
                "APP_POS_CODE":"IBL",
                "APP_IPV_DOC_RECEIVED":"02",
		#"APP_AMC":"IBL",
                "APP_AMC":"IBL",#
		"APP_APPLICANT_CITIZENSHIP": "01",
		"APP_OCCUPATION": app_occupation, # implies others
		"APP_APPLICANT_KYC_ACC_TYPE": "01",
		"APP_EKYC_TYPE": "I",
		#"APP_PER_COUNTRY": country_mapper.get(request_raw_data.get("APP_PER_COUNTRY","IN"),"India"),
                "APP_PER_COUNTRY":"101",
		"APP_KYC_EMP_NAME": request_raw_data.get("app_name","abctest123"),
	    "APP_KYC_EMP_CODE": "00028",
	    "APP_KYC_EMP_BRANCH": "PWI",
	    "APP_KYC_EMP_DESIGNATION": "Head of OPS",
	    "APP_KYC_INSTITUTION_CODE": "P",
	    "APP_KYC_INSTITUTION_NAME": "ICICIBANK",
	    "APP_KRA_INFO": "eKYC-eIPV",
	    "APP_PAN_COPY": "Y",
	    "APP_FATCA_TAX_JURISDICTION": "N",
    	"APP_FATCA_REL_PERSON": "N",
    	"APP_EXMT_CAT": "N",
    	"APP_RELATIONSHIP": "F",
    	"APP_PLACE_DECLARATION": "Online",
    	"APP_COMM_ADDR_PROOF": "31",# implies aadhaar
    	"APP_PER_ADDR_PROOF": "31",# 
    	"APP_COMM_ADDR_TYPE": "02",# implies residential
    	"APP_COMM_MOBILE_NO_CODE": "91",
    	#"APP_COMM_COUNTRY": country_mapper.get(request_raw_data.get("APP_COMM_COUNTRY","IN"),"India"),
        "APP_COMM_COUNTRY":"101",
    	"APP_ID_PROOF": "02",
    	"APP_FATHER_TITLE": "Mr",
    	"APP_APPLICANT_STATUS": "R",
    	"APP_MARITAL_STATUS":"03", # 03 implies others
        "KYC_TYPE":"5",
        "APP_FATCA_APPLICABLE_FLAG":"Y"
        #"fatca":{
            #"APP_FATCA_BIRTH_PLACE":"Mumbai",
            #"APP_FATCA_COUNTRY_BIRTH":"101",
            #"APP_FATCA_COUNTRY_CITYZENSHIP":"101",
            #"APP_FATCA_DATE_DECLARATION":"26/07/2024",
            #"APP_POL_CONN":"PEP",
            #"GROSS_ANNUAL_INCOME":"500000",
            # "APP_NETWRTH":"500000",
            #"APP_FATCA_COUNTRY_RESIDENCY_1":"101",
            #"APP_FATCA_TAX_IDENTIFICATION_NO_1":"GEXPD8653H",
            #"APP_FATCA_TAX_EXEMPT_FLAG_1":"Y",
            #"APP_FATCA_TAX_EXEMPT_REASON_1":"some reason",
            #"APP_FATCA_COUNTRY_RESIDENCY_2":"101",
            #"APP_FATCA_TAX_IDENTIFICATION_NO_2":"GEXPD8653H",
            #"APP_FATCA_TAX_EXEMPT_FLAG_2":"Y",
            #"APP_FATCA_TAX_EXEMPT_REASON_2":"some reason",
            #"APP_FATCA_COUNTRY_RESIDENCY_3":"101",
            #"APP_FATCA_TAX_IDENTIFICATION_NO_3":"GEXPD8653H",
            #"APP_FATCA_TAX_EXEMPT_FLAG_3":"Y",
            #"APP_FATCA_TAX_EXEMPT_REASON_3":"some reason",
            #"APP_FATCA_COUNTRY_RESIDENCY_4":"101",
            #"APP_FATCA_TAX_IDENTIFICATION_NO_4":"GEXPD8653H",
            #"APP_FATCA_TAX_EXEMPT_FLAG_4":"Y",
            #"APP_FATCA_TAX_EXEMPT_REASON_4":"some reason"
        #}
        
        }
	if request_raw_data.get('fatca_flag') not in ["N",None]:
		data["fatca"] = {
			"APP_FATCA_PLACE_BIRTH": country_mapper.get(request_raw_data.get("fatca",{}).get("APP_FATCA_PLACE_BIRTH")),
			"APP_FATCA_COUNTRY_BIRTH": country_mapper.get(request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRY_BIRTH"),"IN"),
			"APP_FATCA_COUNTRY_CITYZENSHIP": request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRY_CITYZENSHIP","IN"),
			"APP_FATCA_DATE_DECLARATION": request_raw_data.get("fatca",{}).get("APP_FATCA_DATE_DECLARATION"),
                        "APP_FATCA_TAX_JURISDICTION":request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_JURISDICTION","Y"),
                        "APP_FATCA_COUNTRYOF_JURISDICTION":country_mapper.get(request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRYOF_JURISDICTION"),"IN"),
			"APP_POL_CONN": pol_mapper.get(request_raw_data.get("fatca",{}).get("APP_POL_CONN")),
			"GROSS_ANNUAL_INCOME": request_raw_data.get("fatca",{}).get("GROSS_ANNUAL_INCOME"),
			# "APP_NETWRTH": request_raw_data.get("fatca",{}).get("APP_NETWRTH"),
			"APP_FATCA_COUNTRY_RESIDENCY_1": request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_1","IN"),
			"APP_FATCA_TAX_IDENTIFICATION_NO_1": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_1"),
			"APP_FATCA_TAX_EXEMPT_FLAG_1": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_1","N"),
			"APP_FATCA_TAX_EXEMPT_REASON_1": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_1"),
			"APP_FATCA_COUNTRY_RESIDENCY_2": request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_2","IN"),
			"APP_FATCA_TAX_IDENTIFICATION_NO_2": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_2","N"),
			"APP_FATCA_TAX_EXEMPT_FLAG_2": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_2"),
			"APP_FATCA_TAX_EXEMPT_REASON_2": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_2"),
			"APP_FATCA_COUNTRY_RESIDENCY_3": request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_3","IN"),
			"APP_FATCA_TAX_IDENTIFICATION_NO_3": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_3","N"),
			"APP_FATCA_TAX_EXEMPT_FLAG_3": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_3"),
			"APP_FATCA_TAX_EXEMPT_REASON_3": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_3"),
			"APP_FATCA_COUNTRY_RESIDENCY_4": request_raw_data.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_4","IN"),
			"APP_FATCA_TAX_IDENTIFICATION_NO_4": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_4","N"),
			"APP_FATCA_TAX_EXEMPT_FLAG_4": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_4"),
			"APP_FATCA_TAX_EXEMPT_REASON_4": request_raw_data.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_4")
		}
	data["APP_KYC_DATE"] = kyc_date
	data["APP_IPV_DATE"] = kyc_date#
	#data["APP_PAN"] = request_raw_data["pan"]
	print(request_raw_data["pan"])
	data["APP_ID_PROOF_IDENTNO"] = request_raw_data["uid"][-4:]
	data["APP_COMM_MOBILE_NO"] = request_raw_data["mobile"]
	data["APP_COMM_EMAIL_ID"] = request_raw_data["email"]
	data["APP_DOC_SOURCE"] = "CAMS"
	data["APP_PER_IDENT_NO"] = request_raw_data["uid"]
	data["APP_COMM_IDENT_NO"] = data["APP_PER_IDENT_NO"]
	data["APP_COMM_PINCODE"] = request_raw_data["pincode"]
	data["APP_PER_PINCODE"] = request_raw_data["pincode"]
	data["APP_COMM_PINCODE"] = data["APP_PER_PINCODE"]
	data["APP_PER_CITY"] = request_raw_data["city"]
	data["APP_COMM_CITY"] = data["APP_PER_CITY"]
	data["APP_GENDER"] = request_raw_data["gender"]
	data["APP_PER_DISTRICT"] = request_raw_data["dist"]
	data["APP_COMM_DISTRICT"] = data["APP_PER_DISTRICT"]
	data["APP_PER_ADDR1"] = request_raw_data["address1"]
	data["APP_PER_ADDR2"] = request_raw_data["address2"]
	data["APP_PER_ADDR3"] = request_raw_data["address3"]
	data["APP_COMM_ADDR1"] = data["APP_PER_ADDR1"]
	data["APP_COMM_ADDR2"] = data["APP_PER_ADDR2"]
	data["APP_COMM_ADDR3"] = data["APP_PER_ADDR3"]
	data["APP_PER_STATE"] = state_master.get(request_raw_data["state"].upper(),"099")
	data["APP_COMM_STATE"] = data["APP_PER_STATE"]
	data["APP_PLACE_DECLARATION"] = request_raw_data["city"] 
	data["APP_DOB"] = dob_date#
	data["APP_DOB_DECLARATION"] = dob_date
	data["APP_DOC_PAN"] = ""
	data["APP_IPV_EMP_NAME"] = request_raw_data.get("APP_IPV_EMP_NAME","ABC")
	data["APP_IPV_EMP_CODE"] = request_raw_data.get("APP_IPV_EMP_CODE","123")
	data["APP_IPV_EMP_DESIGNATION"] = request_raw_data.get("APP_IPV_EMP_DESIGNATION","Manager")
	data["APP_REQ_TYPE"] = ""
	data["APP_IPV_EMP_BRANCH"] = request_raw_data.get("APP_IPV_EMP_BRANCH","MUM")
	data["APP_IPV_INSTITUTION_CODE"] = request_raw_data.get("APP_IPV_INSTITUTION_CODE","10")
	data["APP_IPV_INSTITUTION_NAME"] = "ICICI Bank"
	data["APP_IPV_DONE_BY"] = "ICICI"





	data["APP_APPLICANT_TITLE"] = title_master.get(request_raw_data["gender"],"Mr")#
	data["APP_APPLICANT_F_NAME"] = request_raw_data["name"]#

	data["APP_FATHER_F_NAME"] = "-" if request_raw_data["father_name"] == "" else request_raw_data["father_name"]#
	data["APP_FATHER_L_NAME"] = ""#request_raw_data["name"].split(" ")[-1]#
	data["APP_FATHER_TITLE"] = request_raw_data["salutation"]#
	data["APP_RELATIONSHIP"] = request_raw_data["relation_type"].upper()[0]
	if isinstance(request_raw_data["digib"],bytes):
		data["APP_DOC_ADDR_PROOF"] = request_raw_data["digib"].decode('utf-8')
	data["APP_DOC_ADDR_PROOF"] = request_raw_data["digib"] #Digilocker PDF converted into an image
	if isinstance(request_raw_data["Pht"],bytes):
		data["APP_DOC_PHOTO"] = request_raw_data["Pht"].decode('utf-8')
	data["APP_DOC_PHOTO"] = request_raw_data["Pht"]#aadhaar_photo_b64#"" #Just aadhaar photo
	if isinstance(request_raw_data["sb64"],bytes):
		data["APP_DOC_SIGN"] = request_raw_data["sb64"].decode('utf-8')
	data["APP_DOC_SIGN"] = request_raw_data["sb64"] #signature_photo_b64"" #Just signature photo
	if isinstance(request_raw_data["axml"],bytes):
		data["AADHAR_XML"] = request_raw_data["axml"].decode('utf-8')
	#data["AADHAR_XML"] = request_raw_data["axml"]
	data["AADHAR_PASSCODE"] = request_raw_data.get("AADHAR_PASSCODE","12345")
	data["AADHAR_DIGIT"] = "1"
	data["APP_RESIDENTIAL_STATUS"] = "R"
	#data["APP_DOC_ESIGN_FORM"] = get_base64_from_url("https://s3.ap-south-1.amazonaws.com/uat.vkyc.kwikid/esign/be024ff1-5a34-4248-802e-3c311b4de14b/RUPSA+HALDER_signedFinal.pdf")
	#data["APP_DOC_ESIGN_FORM"] = get_base64_from_url("https://s3.ap-south-1.amazonaws.com/uat.vkyc.kwikid/esign/d6401ba7-3193-4d60-81c7-78a8159be3ec/Esha+Mehra_signedFinal.pdf")
	#data["APP_DOC_ESIGN_FORM"] = get_base64_from_url("https://s3.ap-south-1.amazonaws.com/uat.vkyc.kwikid/esign/0362a65e-3b7e-4d1a-b620-dfcb5e3190b6/Karthi_signedFinal.pdf")
	data["APP_DOC_ESIGN_FORM"] = get_base64_from_url("https://s3.ap-south-1.amazonaws.com/uat.vkyc.kwikid/esign/{}/{}_signedFinal.pdf".format(txnid,nameasperaadhaar.replace(" ","+")))
        #print(data)
	print("pushing for: {}".format(data["APP_PAN"]))
	#print(data)
	return data
	pass



#get_password()


def donit(user_id):
    
    l = open("{}_cams.txt".format(user_id),"r")

    data = eval(l.read())
    l.close()


#reqb = generate_request_body_from_data(data,None,None)
#print(json.dumps(reqb))

#with open("raw.txt","w") as cr:
    
#    cr.write(str(json.dumps(reqb)))

    images = convert_from_path("{}.pdf".format(user_id))

    for i, image in enumerate(images):
        image.save('{}.jpg'.format(user_id), 'JPEG')

        l = open("{}.jpg".format(user_id),"rb")
        i = l.read()
        l.close()

#print(i)

    digib64 = base64.b64encode(i)

#print(digib64)

    #data = json.loads(data)
    with open("pdf_image.txt","w") as f:
        f.write(digib64.decode("utf-8"))

    data["digib"] = digib64.decode("utf-8")
    
    o = open("{}_aadhaar_raw_xml.txt".format(user_id))
    #my_dict = eval(o.read())
    #o.close()
    xml = o.read()
    o.close()

    o = open("{}_txnid.txt".format(user_id))
    #my_dict = eval(o.read())
    #o.close()
    txnid_data = eval(o.read())
    o.close()


# Convert to XML
    #xml = convert_dict_to_xml(my_dict)
    #xml = xmltodict.unparse(my_dict,pretty=True)
    #print("xml----")
    #print(xml)
    xb64 = base64.b64encode(xml.encode())
    # print(xb64)
    print("d")
    data["axml"] = xb64

    reqb = generate_request_body_from_data(data,None,None,txnid_data["txnid"],txnid_data["aadhar_name"],user_id)
    #print("final request payload before encryption->>>",str(reqb))

#print(reqb)

#with open("raw.txt","w") as cr:

#    cr.write(str(json.dumps(reqb)))

    if call_cams_kyc_creation_request(reqb,user_id) == 1:
        session_table = dynamo.Table("kwikid_vkyc_session_status")
        response = session_table.query(
			IndexName="user_id-index",  # Secondary index name
			KeyConditionExpression=Key("user_id").eq(user_id),  # Replace "abc" with your user_id value
			ScanIndexForward=False
		)
        sorted_sessions = sorted(response.get("Items",[]), key=lambda x: x['start_time'], reverse=True)
        if sorted_sessions:
            item = sorted_sessions[0]
            session_id = item["session_id"]
            print("session_id is->>>>>",session_id)
            
            response = session_table.update_item(
				Key={
					"session_id": session_id  # Use session_id as the partition key
				},
				UpdateExpression="SET session_status = :new_status",
				ExpressionAttributeValues={
					":new_status": "kyc_result_rejected"  # New value for session_status
				},
				ReturnValues="UPDATED_NEW"  # Returns the updated attributes
			)
            print("update response->>>>")
            print(response)
        else:
            print("No session was found for",user_id)
    else:
        session_table = dynamo.Table("kwikid_vkyc_session_status")
        response = session_table.query(
			IndexName="user_id-index",  # Secondary index name
			KeyConditionExpression=Key("user_id").eq(user_id),  # Replace "abc" with your user_id value
			ScanIndexForward=False
		)
        sorted_sessions = sorted(response.get("Items",[]), key=lambda x: x['start_time'], reverse=True)
        if sorted_sessions:
            item = sorted_sessions[0]
            session_id = item["session_id"]
            print("session_id is->>>>>",session_id)
            
            response = session_table.update_item(
				Key={
					"session_id": session_id  # Use session_id as the partition key
				},
				UpdateExpression="SET session_status = :new_status",
				ExpressionAttributeValues={
					":new_status": "kyc_result_approved"  # New value for session_status
				},
				ReturnValues="UPDATED_NEW"  # Returns the updated attributes
			)
            print("update response->>>>")
            print(response)
        else:
            print("No session was found for",user_id)

#get_password()
#donit("ICICI_729757999")
#donit("ICICI_73480635")
#donit("ICICI_573996840")
#donit("ICICI_93281518")
#donit("ICICI_895043976")







