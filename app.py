import json
import pdfkit
import base64
import datetime
import requests
from flask import Flask,jsonify,request,redirect,make_response
from flask_cors import CORS
import PyPDF2
import boto3
from config import state_master as sm
from config import country_mapper,pol_mapper
from boto3.dynamodb.conditions import Key


#from make_cams_request import generate_request_body_from_data 

from make_cams_request import donit 

app=Flask(__name__)
CORS(app)
dynamo = boto3.resource('dynamodb',
        region_name='ap-south-1',
        endpoint_url="http://scylla.prod.getkwikid.com:8001/",
        verify=False,
        aws_access_key_id='KIA2YVUKFCK6XQW6KGD',
        aws_secret_access_key='b3lF6qn3lmMJs+1/xZtcvB8NNRMTbMY89wU+CHyu')

pdfkit_config = pdfkit.configuration(wkhtmltopdf="/usr/bin/wkhtmltopdf")

def get_base64_from_url(url):
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

def split_line(input_line):
    segments = input_line.split(',')  # Split the input line into segments based on commas
    max_length = 55
    lines = []  # List to store the resulting lines
    current_line = ""  # Initialize the current line

    for segment in segments:
        segment = segment.strip()  # Trim whitespace from the segment
        # Check if adding the next segment would exceed the max length
        if len(current_line) + len(segment) + 2 > max_length:
            if current_line:  # Ensure the current line is not empty
                lines.append(current_line)  # Add the current line to the list
            current_line = segment  # Start a new line with the current segment
        else:
            if current_line:  # Add a comma and space if this is not the first segment in the line
                current_line += ", "
            current_line += segment

    if current_line:  # Add the last line if it's not empty
        lines.append(current_line)

    return lines

def insert_newline_after_third_comma(s):
    # Initialize an empty list to hold the chunks
    chunks = []
    # Split the string by comma
    parts = s.split(',')
    # Initialize a counter for commas
    comma_count = 0
    # Initialize a temporary string to hold the current chunk
    current_chunk = ""
    
    for part in parts:
        # Add the current part to the chunk
        current_chunk += part + ','
        comma_count += 1
        # If we've added three commas, append the chunk to the list and reset
        if comma_count == 3:
            # Remove the trailing comma from the current chunk
            current_chunk = current_chunk[:-1]
            # Append the chunk to the list and add a newline character
            chunks.append(current_chunk + '\n')
            # Reset the current chunk and comma count
            current_chunk = ""
            comma_count = 0
    
    # Check if there's a remaining chunk that didn't reach 3 commas
    if current_chunk:
        # Remove the trailing comma from the last chunk, if it exists
        chunks.append(current_chunk.rstrip(','))
    
    # Join all the chunks together
    result = ''.join(chunks)
    
    return result

def make_camspdf(user_details,mobile,signature_base64):
    html_template_f = open("full_doc.html")
    html_template = html_template_f.read()
    html_template_f.close()

    aadhaar_details_f = open(mobile+"_aadhaar.txt","r")
    aadhaar_details = eval(aadhaar_details_f.read())
    aadhaar_details_f.close()

    #uiddata = aadhaar_details["aadhaarDetails"]["Certificate"]["CertificateData"]["KycRes"]["UidData"]
    uiddata = aadhaar_details
    poi = uiddata["Poi"]
    poa = uiddata["Poa"]
    print("user_details->>>>>>>>>>>.")
    print(user_details)
    print("modification data->>>>>>>>>>>>>>")
    print(user_details.get("updated_data","no mod data found"))
    mod_data = user_details.get("updated_data","")
    user_details = json.loads(user_details.get("decryptedData"))
    print("residency 1 country",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_1"),"IN"))
    print("residency 2 country",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_2"),"IN"))
    print("residency 3 country",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_3"),"IN"))
    print("residency 4 country",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_4"),"IN"))
    
    html_template = html_template.replace("{pan}",mod_data.get("APP_PAN_NO","NA"))
    html_template = html_template.replace("{mobile}",mod_data.get("APP_MOB_NO","NA"))
    html_template = html_template.replace("{father_name}",mod_data.get("APP_F_NAME","NA"))
    html_template = html_template.replace("{email}",mod_data.get("APP_EMAIL","NA").lower())
    html_template = html_template.replace("{name}",mod_data.get("APP_NAME","NA"))
    html_template = html_template.replace("{dob}",mod_data.get("APP_DOB_DT","NA"))
    html_template = html_template.replace("{state}",sm.get(mod_data.get("APP_PER_STATE",mod_data.get("APP_COR_STATE","NA")),"NA"))
    html_template = html_template.replace("{masked_aadhaar_number}",uiddata["@uid"])
    html_template = html_template.replace("{city}",mod_data.get("APP_PER_CITY","NA"))
    html_template = html_template.replace("{pincode}",mod_data.get("APP_PER_PINCD","NA"))
    html_template = html_template.replace("{gender}",mod_data.get("APP_GEN","NA"))

    html_template = html_template.replace("{place_of_birth}",user_details.get("fatca",{}).get("APP_FATCA_BIRTH_PLACE",""))
    html_template = html_template.replace("{country_of_birth}",str(country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_BIRTH_COUNTRY"),"IN")))
    html_template = html_template.replace("{country_of_citizenship}",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_CITYZENSHIP"),"IN"))
    html_template = html_template.replace("{date_of_declaration}",user_details.get("fatca",{}).get("APP_FATCA_DATE_DECLARATION",""))
    html_template = html_template.replace("{political_connection}",pol_mapper.get(user_details.get("fatca",{}).get("APP_POL_CONN",""),"NA"))
    html_template = html_template.replace("{gross_annual_income}",str(user_details.get("fatca",{}).get("GROSS_ANNUAL_INCOME","")))
    html_template = html_template.replace("{net_worth}",str(user_details.get("fatca",{}).get("APP_NETWRTH","")))
    html_template = html_template.replace("{country_of_residency_1}",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_1"),"IN"))
    html_template = html_template.replace("{tax_no_1}",user_details.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_1",""))
    html_template = html_template.replace("{tax_exempt_flag_1}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_1",""))
    html_template = html_template.replace("{tax_exempt_1}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_1",""))

    html_template = html_template.replace("{country_of_residency_2}",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_2"),"IN"))
    html_template = html_template.replace("{tax_no_2}",user_details.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_2",""))
    html_template = html_template.replace("{tax_exempt_flag_2}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_2",""))
    html_template = html_template.replace("{tax_exempt_2}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_2",""))

    html_template = html_template.replace("{country_of_residency_3}",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_3"),"IN"))
    html_template = html_template.replace("{tax_no_3}",user_details.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_3",""))
    html_template = html_template.replace("{tax_exempt_flag_3}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_3",""))
    html_template = html_template.replace("{tax_exempt_3}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_3",""))


    html_template = html_template.replace("{country_of_residency_4}",country_mapper.get(user_details.get("fatca",{}).get("APP_FATCA_COUNTRY_RESIDENCY_4"),"IN"))
    html_template = html_template.replace("{tax_no_4}",user_details.get("fatca",{}).get("APP_FATCA_TAX_IDENTIFICATION_NO_4",""))
    html_template = html_template.replace("{tax_exempt_flag_4}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_FLAG_4",""))
    html_template = html_template.replace("{tax_exempt_4}",user_details.get("fatca",{}).get("APP_FATCA_TAX_EXEMPT_REASON_4",""))
   
    html_template = html_template.replace("{photo}",uiddata["Pht"])
    html_template = html_template.replace("{signature_photo}",mod_data.get("APP_SIGNATURE",""))


    field_order = ["co","house","street","loc","lm","po","pc","vtc","subdist","dist","state","country"]

    address = ""
    for field in field_order:
        try:
            field_value = poa["@"+field]
            address = address + field_value + ","
        except:
            pass

    address = address[:-1]
    address = split_line(address)
    print(address)
    print(len(address))
    address1 = address[0]
    address2 = address[1] if len(address) > 1 else ""
    address3 = address[2] if len(address) > 2 else ""

    html_template = html_template.replace("{address1}",str(mod_data.get("APP_PER_ADD1",mod_data.get("APP_COR_ADD1","NA"))))
    html_template = html_template.replace("{address2}",str(mod_data.get("APP_PER_ADD2",mod_data.get("APP_COR_ADD2","NA"))))
    html_template = html_template.replace("{address3}",str(mod_data.get("APP_PER_ADD3","")))

    try:
        cams_json = {
                    "pan":user_details["poi"]["pan"],
                    "mobile":user_details["poi"]["mobile"],
                    "email":user_details["poi"]["email_id"],
                    "app_name":user_details["poi"]["name"],
                    "fatca":user_details.get("fatca"),
                    "fatca_flag":user_details.get("APP_FATCA_APPLICABLE_FLAG"),
                    "state":poa["@state"],
                    #"father_name":user_details.get("father_spouse_fullname","NA"),
                    "father_name":mod_data.get("APP_F_NAME","NA"),
                    "relation_type":user_details.get("relation_type","son"),
                    "salutation":user_details.get("salutation","Mr"),
                    "modification_data":mod_data,
                    "name":poi["@name"],
                    "dob":poi["@dob"],
                    "uid":uiddata["@uid"],
                    "city":poa["@vtc"],
                    "gender":poi["@gender"],
                    "pincode":poa["@pc"],
                    "dist":poa["@dist"],
                    "address1":str(mod_data.get("APP_PER_ADD1",mod_data.get("APP_COR_ADD1","NA"))),
                    "address2":str(mod_data.get("APP_PER_ADD2",mod_data.get("APP_COR_ADD2","NA"))),
                    "address3":str(mod_data.get("APP_PER_ADD3",mod_data.get("APP_COR_ADD3","NA"))),
                    "Pht":uiddata["Pht"],
                    "sb64":str(mod_data.get("APP_SIGNATURE",""))
                }
        print("before writing the cams payload->>>>>>>>>>")
        with open(mobile+"_cams.txt","w") as cams:
            cams.write(str(cams_json))
        print("after writing the cams payload->>>>>>>>>>>")
        #reqb = generate_request_body_from_data(cams_json,uiddata["Pht"],signature_base64)
        #with open(str(mobile)+"_camsreq.txt","w") as cams:
        #    cams.write(str(reqb))
    except Exception as e:
        with open(mobile+"_cams.txt","w") as cams:
            cams.write(str(e))
        pass


    print(html_template)
    pdf_bytes = pdfkit.from_string(html_template, str(mobile)+"_cams.pdf", configuration=pdfkit_config,options={'page-size': 'A4'})


def make_pdf(aadhaar_details,mobile,aadhaar_raw_xml):
    print("Inside make_pdf that is inside makeEaadhaarPdf endpoint->>>>>>>>>>>>")
    print("user_id recieved is->>>>>",mobile)
    html_template_f = open("html_ref.html")
    html_template = html_template_f.read()
    html_template_f.close()

    uiddata = aadhaar_details["aadhaarDetails"]["Certificate"]["CertificateData"]["KycRes"]["UidData"]
    print("aadhaar data is->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
    print(uiddata)
    poi = uiddata["Poi"]
    poa = uiddata["Poa"]

    with open(mobile+".txt","w") as ffw:
        ffw.write(str(poi["@name"]))

    with open(mobile+"_aadhaar.txt","w") as aaw:
        aaw.write(str(uiddata))

    with open(mobile+"_aadhaar_raw.txt","w") as aaw:
        aaw.write(str(aadhaar_details["aadhaarDetails"]))


    with open(mobile+"_aadhaar_raw_xml.txt","w") as aaw:
        aaw.write(str(aadhaar_raw_xml))


    html_template = html_template.replace("{name}",poi["@name"])
    html_template = html_template.replace("{dob}",poi["@dob"])
    html_template = html_template.replace("{gender}",poi["@gender"])

    html_template = html_template.replace("{city}",poa.get("@vtc",""))
    html_template = html_template.replace("{pincode}",poa["@pc"])
    html_template = html_template.replace("{co}",poa.get("@co",""))
    html_template = html_template.replace("{landmark}",poa.get("@lm",""))
    html_template = html_template.replace("{locality}",poa.get("@street",""))
    html_template = html_template.replace("{state}",poa["@state"])
    html_template = html_template.replace("{masked_aadhaar_number}",uiddata["@uid"])
    html_template = html_template.replace("{photo}",uiddata["Pht"])
    html_template = html_template.replace("{generation_date}",aadhaar_details["aadhaarDetails"]["Certificate"]["CertificateData"]["KycRes"]["@ts"])
    html_template = html_template.replace("{download_date}",str(datetime.datetime.now()))
    field_order = ["co","house","street","loc","lm","po","pc","vtc","subdist","dist","state","country"]

    address = ""
    for field in field_order:
        try:
            field_value = poa["@"+field]
            address = address + field_value + ","
        except:
            pass

    address = address[:-1]
    address = insert_newline_after_third_comma(address)
    #Split into multiple address lines as an attribute hits the 55 character mark
    html_template = html_template.replace("{address}",address)
    pdf_bytes = pdfkit.from_string(html_template, str(mobile)+".pdf", configuration=pdfkit_config,options={'page-size': 'A4'})
    return "done"

@app.route("/health",methods=["GET"])
def health():
    return "ok"

@app.route("/makeEaadhaarPDF",methods=["POST"])
def makeEaadhaarPDF():
    print("aadhaar xml {}".format(request.json["aadhaar_raw_xml"]))
    return make_pdf(request.json["aadhaar_details"],request.json["mobile"],request.json["aadhaar_raw_xml"])

@app.route("/makeCAMSPDF",methods=["POST"])
def makeCAMSPDF():
    return make_camspdf(request.json["user_details"],request.json["mobile"])

@app.route("/pushtoKRA",methods=["GET","POST"])
def pushtoKRA():
    print("called!!")
    user_id = request.args["user_id"]
    if donit(user_id) == 0:
        return jsonify({"message":"Some problem while pushing the customer data","status_code":500}), 500

    return "ok"

@app.route("/initiateEsign",methods=['POST'])
def initiateEsign():
    filetoread = request.args["mobile"]+"_fullkyc.pdf"
    url = "https://esign.uat.getkwikid.com:8071/dev/sendreq"
    print(request.json["user_details"])
    request_data = request.json["user_details"]
    request_data["updated_data"] = request.json["updated_data"] 

    signature_base64 = get_base64_from_url(request.json["signature_url"])
    #signature_base64 = ""

    make_camspdf(request_data,request.json["mobile"],signature_base64)
    #make_camspdf(request_data,"BAMPM9343K",signature_base64)

    with open(request.args["mobile"]+"_cams.pdf", 'rb') as file1, open(request.args["mobile"]+".pdf", 'rb') as file2:
        reader1 = PyPDF2.PdfReader(file1)
        reader2 = PyPDF2.PdfReader(file2)

    #Create a new PdfWriter object which represents a blank PDF document
        writer = PyPDF2.PdfWriter()

    # Loop through all the pages of the first document and add them
        for pageNum in range(len(reader1.pages)):
            page = reader1.pages[pageNum]
            writer.add_page(page)

    # Loop through all the pages of the second document and add them
        for pageNum in range(len(reader2.pages)):
            page = reader2.pages[pageNum]
            writer.add_page(page)

    # Write out the merged PDF
        with open(filetoread, 'wb') as output_pdf:
            writer.write(output_pdf)

    ffw = open(request.args["mobile"]+".txt","r")
    #ffw = open("BAMPM9343K"+".txt","r")
    name = ffw.read()
    ffw.close()
    payload={'aadhar_name': name, "user_id":request.args["mobile"]}
    #payload={'aadhar_name': name, "user_id":"BAMPM9343K"}
    files=[
    ('file',('file',open('/app/'+filetoread,'rb'),'application/octet-stream'))
    #('file',('file',open('/app/'+"BAMPM9343K.txt",'rb'),'application/octet-stream'))
    ]   
    headers = {
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Origin': 'https://esign.uat.getkwikid.com:8071',
  'Accept-Language': 'en-IN,en-GB;q=0.9,en;q=0.8',
  'Host': 'esign.uat.getkwikid.com:8071',
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15',
  'Referer': 'https://esign.uat.getkwikid.com:8071/esign',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive'
    }   

    response = requests.request("POST", url, headers=headers, data=payload, files=files)
    resp = response.text
    print(resp)
    print(resp.split("txnid\" value=")[1].split("'")[1])
    txnid = resp.split("txnid\" value=")[1].split("'")[1]   
    try:
        with open(request.args["mobile"]+"_txnid.txt","w") as cams:
            cams.write(str({"txnid":str(txnid),"aadhar_name":name,"user_id":request.args["mobile"]}))
        reqb = generate_request_body_from_data(cams_json,uiddata["Pht"],signature_base64)
        with open(str(mobile)+"_camsreq.txt","w") as cams:
            cams.write(str(reqb))
        #with open("8169935304"+"_txnid.txt","w") as cams:
            #cams.write(str({"txnid":str(txnid),"aadhar_name":name,"user_id":"8169935304"}))
        #reqb = generate_request_body_from_data(cams_json,uiddata["Pht"],signature_base64)
        #with open("8169935304"+"_camsreq.txt","w") as cams:
            #cams.write(str(reqb))
    except:
        pass

    print(response.text)
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5156)

