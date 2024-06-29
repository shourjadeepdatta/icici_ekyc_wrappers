import xml.etree.ElementTree as ET

def dict_to_xml(tag, d):
    elem = ET.Element(tag)
    for key, val in d.items():
        if isinstance(val, dict):
            child = dict_to_xml(key, val)
            elem.append(child)
        else:
            child = ET.Element(key)
            child.text = str(val)
            elem.append(child)
    return elem