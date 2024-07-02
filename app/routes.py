from flask import request, Blueprint, g
import requests
from flask import jsonify
import datetime
import base64
import json
import datetime
import os
import io
from PIL import Image
import bcrypt
import jwt
import paramiko
import shutil
import logging
import xml.etree.ElementTree as ET
from app.helpers import dict_to_xml
import xmltodict

bp = Blueprint("v1",__name__)

# logger = logging.getLogger(__name__)

# logging.basicConfig(
#     filename=os.getcwd()+"/logs/error.log",  # Specify the path to the log file
#     level=logging.DEBUG,  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Define the format of the log messages
# )

# logger.setLevel(logging.DEBUG)

@bp.route('/ekyc_verify', methods=['POST'])
def ekyc_verify():
    data = request.get_json()

    if data is None:
        return jsonify({"message":"request payload is empty","status_code":400}), 400
    
    current_datetime = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    root_data = {
        "APP_REQ_ROOT": {
            "APP_PAN_INQ": {
                "APP_PAN_NO": data.get("APP_PAN_NO"),
                "APP_PAN_DOB": data.get("APP_PAN_DOB"),
                "APP_IOP_FLG": data.get("APP_IOP_FLG"),# this part is different for verify part
                "APP_POS_CODE": data.get("APP_POS_CODE"),
            },
            "APP_SUMM_REC": {
                "APP_OTHKRA_CODE": data.get("APP_OTHKRA_CODE"),
                "APP_OTHKRA_BATCH": data.get("APP_OTHKRA_BATCH"),
                "APP_REQ_DATE": current_datetime,
                "APP_TOTAL_REC": data.get("APP_TOTAL_REC"),
            },
        }
    }

    root = dict_to_xml("APP_REQ_ROOT", root_data["APP_REQ_ROOT"])
    input_xml = ET.tostring(root, encoding="unicode")

    soap_envelope = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
    <soap12:Body>
        <VerifyPANDetails_eKYC xmlns="https://camskra.com/">
        <InputXML>{input_xml}</InputXML>
        <USERNAME>THINKEKYC</USERNAME>
        <POSCODE>L</POSCODE>
        <PASSWORD>Sb0j0j0GuBBCgOUVITiJaw==</PASSWORD>
        <PASSKEY>UAT</PASSKEY>
        </VerifyPANDetails_eKYC>
    </soap12:Body>
    </soap12:Envelope>"""
    print("the xml payload is ->>>",soap_envelope)

    api_url = 'https://eiscuat1.camsonline.com/cispl/services_kycenquiry_uat.asmx'

    headers = {'Content-Type': 'application/soap+xml; charset=utf-8'}

    response = requests.post(api_url, data=soap_envelope, headers=headers, verify=False,timeout=100)
    # print("final payload ->>>",soap_envelope)
    print("response is ->>>",response.text)
    print("ekyc_response_status_code->>",response.status_code)
    if response.status_code == 200:
        xml_response = response.content.decode('utf-8')
        json_response = xmltodict.parse(xml_response)
        final_resp = json_response.get("soap:Envelope",{}).get("soap:Body",{}).get("VerifyPANDetails_eKYCResponse",{}).get("VerifyPANDetails_eKYCResult",{}).get("APP_RES_ROOT",{}).get("APP_PAN_INQ")
        if final_resp is None:
            return jsonify({"message":"cams api failed","status_code":500}), 500
        
        print("final_resp is ->>>",final_resp)
        ndml_kra = final_resp.get("NDMLKRA")
        cams_kra = final_resp.get("CAMSKRA")
        cvl_kra = final_resp.get("CVLKRA")
        dot_exkra = final_resp.get("DOTEXKRA")
        karvy_kra = final_resp.get("KARVYKRA")
        ndml_kra = "02"
        print("kra is ->>>",ndml_kra)
        if ndml_kra in ["02","04","07"] or cams_kra in ["02","04","07"] or cvl_kra in ["02","04","07"] or dot_exkra in ["02","04","07"] or karvy_kra in ["02","04","07"]:
            download_payload = {
                "APP_PAN_NO":data.get("APP_PAN_NO"),
                "APP_PAN_DOB":data.get("APP_PAN_DOB"),
                "APP_POS_CODE":data.get("APP_POS_CODE"),
                "APP_OTHKRA_CODE":data.get("APP_OTHKRA_CODE"),
                "APP_OTHKRA_BATCH":data.get("APP_OTHKRA_BATCH"),
                "APP_IOP_FLG":data.get("APP_IOP_FLG"),
                "APP_TOTAL_REC":data.get("APP_TOTAL_REC")
            }
            headers = {"content_type":"application/json"}
            try:
                down_response = requests.request("POST","http://localhost:5000/ekyc_download",data=json.dumps(download_payload),headers=headers,verify=False,timeout=100)
                print("download_wrapper_response is->>>",down_response.text)
                download_response = down_response.json()
                print("json respone->>",download_response)
                if down_response.status_code == 200:
                    return jsonify(download_response), 200
            except Exception as e:
                print(str(e))
                return jsonify({"message":"some problem while calling the download wrapper","error":str(e),"status_code":500}), 500
        
        
    
    return jsonify({"error": "Failed to send request", "status_code": 500}), 500


@bp.route('/ekyc_download', methods=['POST'])
def ekyc_download():
    data = request.get_json()
    
    if data is None:
        return jsonify({"message":"request payload is empty","status_code":400}), 400
    
    current_datetime = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    
    root_data = {
        "APP_REQ_ROOT": {
            "APP_PAN_INQ": {
                "APP_PAN_NO": data.get("APP_PAN_NO"),
                "APP_PAN_DOB": data.get("APP_PAN_DOB"),
                "APP_IOP_FLG": data.get("APP_IOP_FLG"),# this should be different for download part
                "APP_POS_CODE": data.get("APP_POS_CODE"),
            },
            "APP_SUMM_REC": {
                "APP_OTHKRA_CODE": data.get("APP_OTHKRA_CODE"),
                "APP_OTHKRA_BATCH": data.get("APP_OTHKRA_BATCH"),
                "APP_REQ_DATE": current_datetime,
                "APP_TOTAL_REC": data.get("APP_TOTAL_REC"),
            },
        }
    }

    root = dict_to_xml("APP_REQ_ROOT", root_data["APP_REQ_ROOT"])
    xml_str = ET.tostring(root, encoding="unicode")
    print("the xml payload is ->>>",xml_str)

    api_url = 'https://eiscuat1.camsonline.com/cispl/services_kycenquiry_uat.asmx'

    soap_envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <DownloadPANDetails_eKYC xmlns="https://camskra.com/">
      <InputXML>{xml_str}</InputXML>
      <USERNAME>THINKEKYC</USERNAME>
      <POSCODE>L</POSCODE>
      <PASSWORD>Sb0j0j0GuBBCgOUVITiJaw==</PASSWORD>
      <PASSKEY>UAT</PASSKEY>
    </DownloadPANDetails_eKYC>
  </soap12:Body>
</soap12:Envelope>"""
    print("the xml payload is ->>>",soap_envelope)

    headers = {'Content-Type': 'application/soap+xml; charset=utf-8'}
    response = requests.post(api_url, data=soap_envelope, headers=headers, verify=False,timeout=100)
    print(response.text)
    if response.status_code == 200:
        xml_response = response.content.decode('utf-8')
        json_response = xmltodict.parse(xml_response)
        final_resp = json_response.get("soap:Envelope",{}).get("soap:Body",{}).get("DownloadPANDetails_eKYCResponse",{}).get("DownloadPANDetails_eKYCResult",{}).get("ROOT",{}).get("KYC_DATA")
        print("final_resp->>>",final_resp)
        if final_resp is None:
            return jsonify({"message":"cams api failed","status_code":500}), 500
        
        return jsonify(final_resp), 200
    
    return jsonify({"error": "Failed to send request", "status_code": response.status_code}), response.status_code