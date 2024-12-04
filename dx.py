import dicttoxml
from xml.dom.minidom import parseString
import base64

def custom_item_func(x):
    # Check if the key starts with '@', which indicates it should be an element itself
    if isinstance(x, tuple) and len(x) == 2 and x[0].startswith('@'):
        return x[0][1:], x[1]
    return x

def custom_item_func(parent):
    def convert(key, val):
        # Check if key starts with '@' and create a tag with the rest of the key
        if key.startswith('@'):
            key = key[1:]
        return key, val
    return convert

def convert_dict_to_xml(dict_data):
    # Convert the dictionary to an XML byte string
    xml_bytes = dicttoxml.dicttoxml(dict_data, root=False, attr_type=False)#, item_func=custom_item_func(dict_data))
    # Convert bytes to a string
    xml_str = xml_bytes.decode()
    # Use minidom to make the output a pretty XML format
    dom = parseString(xml_str)
    return dom.toprettyxml()

# Example dictionary
#my_dict = {'name': 'John', 'age': 30, 'city': 'New York'}

o = open("ICICI_93281518_aadhaar_raw.txt")
my_dict = eval(o.read())
o.close()



# Convert to XML
xml = convert_dict_to_xml(my_dict)
print(xml)


print(base64.b64encode(xml.encode()))
