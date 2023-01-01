import requests
import time
ip ="127.0.0.1"
def read_and_post():
    file1 = open('records.xml', 'r')
    Lines = file1.readlines()
    for line in Lines:
        headers = {'Content-Type': 'application/xml'}
        print(requests.post("http://"+ip+":5000/product",data=line,headers=headers))

read_and_post()
