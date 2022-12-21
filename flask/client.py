import requests
import time
ip ="127.0.0.1"
def sendxml():
    xml = """<?xml version="1.0" encoding="UTF-8" ?>
<root>
    <description type="str">This is updated description of product 2</description>
    <id type="int">2</id>
    <name type="str">Product 2</name>
    <price type="float">30.01</price>
    <qty type="int">70</qty>
</root>"""
    headers = {'Content-Type': 'application/xml'}
    print(requests.post("http://"+ip+"5000/product",data=xml,headers=headers))
while True:
    try:
        time.sleep(3)
        sendxml()
    except Exception as e:
        print("Network Error: ",e)