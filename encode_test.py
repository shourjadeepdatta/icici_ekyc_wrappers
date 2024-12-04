import urllib.parse

# Sample JSON payload
payload = {
    "APP_UPLOAD_TYPE": "03",
    "APP_USER_ID": "IBLIPRULIV",
    "APP_PAN": "BAMPM9343K",
    "APP_OTHER_KRA": "IBLIPRULIV",
    "APP_PASSKEY": "LIVE",
    "APP_POS_CODE": "CK0005",
    "APP_IPV_DOC_RECEIVED": "02",
    "APP_AMC": "P",
    "APP_APPLICANT_CITIZENSHIP": "01",
    "APP_OCCUPATION": "99",
    "APP_APPLICANT_KYC_ACC_TYPE": "01",
    "APP_EKYC_TYPE": "I",
    "APP_PER_COUNTRY": "101",
    "APP_KYC_EMP_NAME": "Abhishek",
    "APP_KYC_EMP_CODE": "00028",
    "APP_KYC_EMP_BRANCH": "PWI",
    "APP_KYC_EMP_DESIGNATION": "Head",
    "APP_KYC_INSTITUTION_CODE": "IBL",
    "APP_KYC_INSTITUTION_NAME": "ICICIBANK",
    "APP_KRA_INFO": "eKYC-eIPV",
    "APP_PAN_COPY": "Y",
    "APP_FATCA_TAX_JURISDICTION": "N",
    "APP_FATCA_REL_PERSON": "N",
    "APP_EXMT_CAT": "N",
    "APP_RELATIONSHIP": "S",
    "APP_PLACE_DECLARATION": "Mumbai",
    "APP_COMM_ADDR_PROOF": "31",
    "APP_PER_ADDR_PROOF": "31",
    "APP_COMM_ADDR_TYPE": "02",
    "APP_COMM_MOBILE_NO_CODE": "91",
    "APP_COMM_COUNTRY": "101",
    "APP_ID_PROOF": "01",
    "APP_FATHER_TITLE": "Mr",
    "APP_APPLICANT_STATUS": "R",
    "APP_MARITAL_STATUS": "03",
    "KYC_TYPE": "5",
    "APP_FATCA_APPLICABLE_FLAG": "Y",
    "fatca": {
        "APP_FATCA_BIRTH_PLACE": "Mumbai",
        "APP_FATCA_BIRTH_COUNTRY": "IN",
        "APP_FATCA_COUNTRY_CITYZENSHIP": "IN",
        "APP_FATCA_DATE_DECLARATION": "26/07/2024",
        "APP_POL_CONN": "PEP",
        "GROSS_ANNUAL_INCOME": "500000",
        "APP_NETWRTH": "500000",
        "APP_FATCA_COUNTRY_RESIDENCY_1": "India",
        "APP_FATCA_TAX_IDENTIFICATION_NO_1": "GEXPD8653H",
        "APP_FATCA_TAX_EXEMPT_FLAG_1": "Y",
        "APP_FATCA_TAX_EXEMPT_REASON_1": "some",
        "APP_FATCA_COUNTRY_RESIDENCY_2": "IN",
        "APP_FATCA_TAX_IDENTIFICATION_NO_2": "GEXPD8653H",
        "APP_FATCA_TAX_EXEMPT_FLAG_2": "Y",
        "APP_FATCA_TAX_EXEMPT_REASON_2": "some",
        "APP_FATCA_COUNTRY_RESIDENCY_3": "India",
        "APP_FATCA_TAX_IDENTIFICATION_NO_3": "GEXPD8653H",
        "APP_FATCA_TAX_EXEMPT_FLAG_3": "Y",
        "APP_FATCA_TAX_EXEMPT_REASON_3": "some",
        "APP_FATCA_COUNTRY_RESIDENCY_4": "India",
        "APP_FATCA_TAX_IDENTIFICATION_NO_4": "GEXPD8653H",
        "APP_FATCA_TAX_EXEMPT_FLAG_4": "Y",
        "APP_FATCA_TAX_EXEMPT_REASON_4": "some"
    },
    "APP_KYC_DATE": "23-Oct-2024",
    "APP_IPV_DATE": "23-Oct-2024",
    "APP_ID_PROOF_IDENTNO": "BAMPM9343K",
    "APP_COMM_MOBILE_NO": "8007353018",
    "APP_COMM_EMAIL_ID": "gajanand@valuefy.com",
    "APP_DOC_SOURCE": "CAMS",
    "APP_PER_IDENT_NO": "xxxxxxxx3763",
    "APP_COMM_IDENT_NO": "xxxxxxxx3763",
    "APP_COMM_PINCODE": "400101",
    "APP_PER_PINCODE": "400101",
    "APP_PER_CITY": "Mumbai",
    "APP_COMM_CITY": "Mumbai",
    "APP_GENDER": "M",
    "APP_PER_DISTRICT": "Mumbai Suburban",
    "APP_COMM_DISTRICT": "Mumbai Suburban",
    "APP_PER_ADDR1": "C/O SUBHRAJYOTI DATTA",
    "APP_PER_ADDR2": "NG SUNCITY PHASE 3 CO OP HSG SOC LTD, THAKUR VILLAGE",
    "APP_PER_ADDR3": "KANDIVALI EAST, Kandivali East,400101, Mumbai",
    "APP_COMM_ADDR1": "C/O SUBHRAJYOTI DATTA,702 BUILDING NO 1 WING C",
    "APP_COMM_ADDR2": "NG SUNCITY PHASE 3 CO OP HSG SOC LTD, THAKUR VILLAGE",
    "APP_COMM_ADDR3": "KANDIVALI EAST, Kandivali East,400101, Mumbai",
    "APP_PER_STATE": "027",
    "APP_COMM_STATE": "027",
    "APP_DOB": "28-Dec-2001",
    "APP_DOB_DECLARATION": "28-Dec-2001",
    "APP_DOC_PAN": "",
    "APP_IPV_EMP_NAME": "ABC",
    "APP_IPV_EMP_CODE": "123",
    "APP_IPV_EMP_DESIGNATION": "Manager",
    "APP_REQ_TYPE": "2",
    "APP_IPV_EMP_BRANCH": "MUM",
    "APP_IPV_INSTITUTION_CODE": "10",
    "APP_IPV_INSTITUTION_NAME": "ICICI Bank",
    "APP_IPV_DONE_BY": "ICICI",
    "APP_APPLICANT_TITLE": "Mr",
    "APP_APPLICANT_F_NAME": "Shourjadeep",
    "APP_FATHER_F_NAME": "Subhrajyoti",
    "APP_FATHER_L_NAME": "",
}

# Flatten the nested dictionary
def flatten_dict(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

flattened_payload = flatten_dict(payload)

# URL encode the flattened dictionary
url_encoded_payload = urllib.parse.urlencode(flattened_payload)

# Print URL-encoded string
print(url_encoded_payload)

