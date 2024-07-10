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
from app.helpers import CAMSEncryptionCKYC, CAMSDecryptionCKYC
import uuid
import pytz

bp = Blueprint("v1",__name__)

logger = logging.getLogger(__name__)

logging.basicConfig(
    filename=os.getcwd()+"/logs/error.log",  # Specify the path to the log file
    level=logging.DEBUG,  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Define the format of the log messages
)

logger.setLevel(logging.DEBUG)

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
    logger.debug("the xml payload is ->>>"+soap_envelope)

    api_url = 'https://eiscuat1.camsonline.com/cispl/services_kycenquiry_uat.asmx'

    headers = {'Content-Type': 'application/soap+xml; charset=utf-8'}

    response = requests.post(api_url, data=soap_envelope, headers=headers, verify=False,timeout=100)
    # logger.debug("final payload ->>>",soap_envelope)
    logger.debug("response is ->>>"+response.text)
    logger.debug("ekyc_response_status_code->>"+str(response.status_code))
    if response.status_code == 200:
        xml_response = response.content.decode('utf-8')
        json_response = xmltodict.parse(xml_response)
        final_resp = json_response.get("soap:Envelope",{}).get("soap:Body",{}).get("VerifyPANDetails_eKYCResponse",{}).get("VerifyPANDetails_eKYCResult",{}).get("APP_RES_ROOT",{}).get("APP_PAN_INQ")
        if final_resp is None:
            return jsonify({"message":"cams api failed","status_code":500}), 500
        
        logger.debug("final_resp is ->>>"+json.dumps(final_resp))
        ndml_kra = final_resp.get("NDMLKRA")
        cams_kra = final_resp.get("CAMSKRA")
        cvl_kra = final_resp.get("CVLKRA")
        dot_exkra = final_resp.get("DOTEXKRA")
        karvy_kra = final_resp.get("KARVYKRA")
        ndml_kra = "02"
        logger.debug("kra is ->>>"+ndml_kra)
        if ndml_kra in ["02","04","07"] or cams_kra in ["02","04","07"] or cvl_kra in ["02","04","07"] or dot_exkra in ["02","04","07"] or karvy_kra in ["02","04","07"]:
            #download_payload = {
                #"APP_PAN_NO":data.get("APP_PAN_NO"),
                #"APP_PAN_DOB":data.get("APP_PAN_DOB"),
                #"APP_POS_CODE":data.get("APP_POS_CODE"),
                #"APP_OTHKRA_CODE":data.get("APP_OTHKRA_CODE"),
                #"APP_OTHKRA_BATCH":data.get("APP_OTHKRA_BATCH"),
                #"APP_IOP_FLG":data.get("APP_IOP_FLG"),
                #"APP_TOTAL_REC":data.get("APP_TOTAL_REC")
            #}
            #headers = {"content_type":"application/json"}
            #try:
                #logger.debug("download_payload->>>>"+json.dumps(download_payload))
                #down_response = requests.request("POST","https://api-dev.test.getkwikid.com/kyc/ekyc_download",data=json.dumps(download_payload),headers=headers,verify=False,timeout=1000)
                #logger.debug("download_wrapper_response is->>>"+down_response.text)
                #download_response = down_response.json()
                #logger.debug("json respone->>"+json.dumps(download_response))
                #if down_response.status_code == 200:
                    #return jsonify(download_response), 200
            #except Exception as e:
                #logger.debug(str(e))
                #return jsonify({"message":"some problem while calling the download wrapper","error":str(e),"status_code":500}), 500
        
        
    
    #return jsonify({"error": "Failed to send request", "status_code": 500}), 500
    
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
            logger.debug("the xml payload is ->>>"+xml_str)

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
            logger.debug("the xml payload is ->>>"+soap_envelope)

            headers = {'Content-Type': 'application/soap+xml; charset=utf-8'}
            down_response = requests.post(api_url, data=soap_envelope, headers=headers, verify=False,timeout=100)
            logger.debug(down_response.text)
            if down_response.status_code == 200:
                xml_response = down_response.content.decode('utf-8')
                json_response = xmltodict.parse(xml_response)
                final_resp = json_response.get("soap:Envelope",{}).get("soap:Body",{}).get("DownloadPANDetails_eKYCResponse",{}).get("DownloadPANDetails_eKYCResult",{}).get("ROOT",{}).get("KYC_DATA")
                logger.debug("final_resp->>>"+json.dumps(final_resp))
                if final_resp is None:
                    return jsonify({"message":"cams api failed","status_code":500}), 500
                
                return jsonify(final_resp), 200
            
        return jsonify({"error": "Failed to send request", "status_code": response.status_code}), response.status_code
    pass


@bp.route("/check_liveliness",methods=["POST"])
def liveliness():
    payload = request.get_json()

    current_time = datetime.datetime.now(pytz.utc)

    # Add 5 hours and 30 minutes
    time_delta = datetime.timedelta(hours=5, minutes=30)
    new_time = current_time + time_delta

    # Format the new time as a string
    formatted_new_time = new_time.strftime('%Y-%m-%dT%H:%M:%S')

    logger.debug("New Timestamp (UTC + 5:30):"+str(formatted_new_time))

    payload["UserID"] = "ICSDK360_UAT"
    payload["Password"] = "bzqUnl1g7At2NlS"
    payload["DocumentIDRefNo"] = str(uuid.uuid4())
    payload["TimeStamp"] = str(formatted_new_time)
    payload["SessionID"] = str(uuid.uuid4())

    logger.debug("normal payload->>>"+json.dumps(payload))

    encrypted_data_payload_for_api = CAMSEncryptionCKYC(payload)


    url = "https://digitalapiuat.camsonline.com/CAMSServiceSuite/api/CAMSLiveness"

    headers = {"Authorization":"Bearer dGVzdGluZyBkYXRhIGZvciBDQU1TIFBBTiBWYWxpZGF0aW9uIEFQSSBJbnRlZ3JhdGlvbiA="}

    # logger.debug("headers->>",headers)
    logger.debug("encrypted payload final->>>"+encrypted_data_payload_for_api)


    try:
        response = requests.post(url,headers=headers,data=encrypted_data_payload_for_api,verify=False,timeout=100)
        logger.debug("encrypted response->>>"+response.text)
        decrypted_response = CAMSDecryptionCKYC(response.text)
        return jsonify(json.loads(decrypted_response))
    except Exception as e:
        logger.debug("some problem->>>"+str(e))

    return jsonify({"message":"error while fetching the liveliness","status_code":400}), 400

