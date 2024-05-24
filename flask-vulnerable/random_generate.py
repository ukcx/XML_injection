from dicttoxml import dicttoxml
import random
import json
from json import loads

prodNameArr = ["iPhone 14 Pro", "iPhone 14 Pro Max", "Apple iPhone X", "Apple Watch 8", "Apple iPhone 13 Pro Max", "Apple iPhone 13 mini", "Apple iPad Air", "Apple AirPods 3", "Apple Watch", "Galaxy Z Fold 4", "Galaxy Watch 5 Pro", "Galaxy S22 Ultra", "Galaxy Z Fold 3", "Galaxy Z Flip 3", "Galaxy Watch 4", "Galaxy Tab S8 Ultra", "Galaxy S21+ 5G", "OnePlus 9 Pro", "OnePlus Nord N10 5G", "Huawei Freebuds Studio", "Huawei Mate 40 Pro", 
"Huawei P40 Pro", "Huawei Watch GT 2 Pro"]

for i in range(1000):
    dictionary = {
        "name": prodNameArr[random.randint(0, len(prodNameArr)-1)],
        "price": random.randint(100, 1000),
        "qty": random.randint(5, 50),
        }
    json_object = json.dumps(dictionary, indent=3) 
    xml_object = dicttoxml(loads(json_object))
    with open("records.xml", "a") as outfile:
        outfile.write(str(xml_object) + '\n')
    
        



