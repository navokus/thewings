import socket
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import os
import subprocess

from collections import namedtuple
from ctypes import byref, create_unicode_buffer, windll
from ctypes.wintypes import DWORD
from itertools import count
import platform
from bs4 import BeautifulSoup
import requests 
import re
import thread

UID_BUFFER_SIZE = 39
PROPERTY_BUFFER_SIZE = 256 
ERROR_MORE_DATA = 234
ERROR_INVALID_PARAMETER = 87
ERROR_SUCCESS = 0
ERROR_NO_MORE_ITEMS = 259 
ERROR_UNKNOWN_PRODUCT = 1605
  

PRODUCT_PROPERTIES = [u'Language',
                      u'ProductName',
                      u'PackageCode',
                      u'Transforms',
                      u'AssignmentType',
                      u'PackageName',
                      u'InstalledProductName',
                      u'VersionString',
                      u'RegCompany',
                      u'RegOwner',
                      u'ProductID',
                      u'ProductIcon',
                      u'InstallLocation',
                      u'InstallSource',
                      u'InstallDate',
                      u'Publisher',
                      u'LocalPackage',
                      u'HelpLink',
                      u'HelpTelephone',
                      u'URLInfoAbout',
                      u'URLUpdateInfo',]
  

Product = namedtuple('Product', PRODUCT_PROPERTIES)
  
  
def get_property_for_product(product, property, buf_size=PROPERTY_BUFFER_SIZE):
        property_buffer = create_unicode_buffer(buf_size)
        size = DWORD(buf_size)
        result = windll.msi.MsiGetProductInfoW(product, property, property_buffer,
                                               byref(size))
        if result == ERROR_MORE_DATA:
                return get_property_for_product(product, property,
                    2 * buf_size)
        elif result == ERROR_SUCCESS:
                return property_buffer.value
        else:
                return None
  
  
def populate_product(uid):
        properties = []
        for property in PRODUCT_PROPERTIES:
                properties.append(get_property_for_product(uid, property))
        return Product(*properties) 
  
  
def get_installed_products_uids():
        products = []
        for i in count(0):
                uid_buffer = create_unicode_buffer(UID_BUFFER_SIZE)
                result = windll.msi.MsiEnumProductsW(i, uid_buffer)
                if result == ERROR_NO_MORE_ITEMS:
                        break
                products.append(uid_buffer.value)
        return products
  
  
def get_installed_products():
        products = []
        for puid in  get_installed_products_uids():
                products.append(populate_product(puid))
        return products 
  
  
def is_product_installed_uid(uid):
        buf_size = 256
        uid_buffer = create_unicode_buffer(uid)
        property = u'VersionString'
        property_buffer = create_unicode_buffer(buf_size)
        size = DWORD(buf_size)
        result = windll.msi.MsiGetProductInfoW(uid_buffer, property, property_buffer,
                                               byref(size))
        if result == ERROR_UNKNOWN_PRODUCT:
                return False
        else:
                return True
 
def cve (vendor, product, version):
        url = "http://www.cvedetails.com/version-search.php?vendor%s=&product=%s&version=%s" %(vendor,product,version)
        f = open("CVE.txt", "a")
        f.write("\n" + product + " " + version + " ")

        req1=requests.get(url)
        soup=BeautifulSoup(req1.text)
        for td in soup.findAll("div", { "class":"paging" }):
                for i in td.findAll('a', href=True):
                        url2 = "https://www.cvedetails.com"+i['href']
                        req2 = requests.get(url2) 
                        soup2=BeautifulSoup(req2.text)
                        for tf in soup2.findAll("tr", { "class":"srrowns" }):
                                for i2 in tf.find("td", {"nowrap":"nowrap"}):
                                        f.write(i2.getText()+", ")
        f.close()

'''#def update (product, version):
    print product
    url = "https://chocolatey.org/packages?q=%s" %product
    #raw_input(url + ' ?')
    req = requests.get(url, verify=False)
    raw_input(url)
    if 'returned 0 packages' in req.text:
        raw_input('wtf')
        return None
    data = req.text
    i = data.find('searchResults')
    data = data[i + len('searchResults'):]
    data = data.split('<div class="side">')
    data = data[:5]
    for p in data:
        i = p.find('href ="')
        j = p.find('" title=')
        package_url = p[i + len('href ="') : j]
        print package_url
        if product in package_url:
            print package_url
        raw_input('Done>')
'''

def writeCVE():
        if platform.system() == 'Windows':
                apps=get_installed_products()
                apps_dict = {}
                for app in apps:
                        if app.InstalledProductName !=None and u'\u2122' not in app.InstalledProductName:
                                count = 0
                                product = ''
                                version = ''

                                for word in app.ProductName.split():
                                        if count == 4:
                                                break
                                        else:
                                                if word == "Microsoft":
                                                        continue
                                                else:
                                                        product = product + ' ' + word
                                                        count+=1
                                product = re.sub(r'[\/:*?"><|]', ' ', product)
                                product = re.sub('\d+.\d+.\d+.\d+.*', '', product)
                                product = re.sub('\d+.\d+.\d+.*', '', product)
                                product = re.sub('\d+.\d+.*', '', product)

                                count = 0
                        if len(app.VersionString) > 4:
                                for i in app.VersionString:
                                                if i == '.':
                                                        count +=1
                                                if count != 2:
                                                        version = version + i
                                                else:
                                                        break
                                apps_dict[product] = version
                             
        #print apps_dict
        for key, value in apps_dict.iteritems():
                cve(app.Publisher, key, value)



class Agent():

        def __init__(self, server_ip, server_port):
                self.con = socket.socket()
                self.con.connect((server_ip, int(server_port)))
                self.server_pub = RSA.importKey('-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwsHeK+VWRn1wxxMu/aP\nU0uK+GtqQDCRIPbr725GoflhSBRT0G+RcNwh3Av77TVQyV/OYqYmXcwoNUtRYYly\nKBsOCt8t2augWId41ijMjfIK1X/oRaNCNI5Wes6PoBBkd7o8AtfnrEFQtb7bs5NT\nBUbg29HdoLxJ7QRFKcuq4NyihdbCzWN5hlI5jPAz3Mofz9cms4WOftHt1MwIpcTz\nhQODbidYN9GnjTkkUa73v5Srgoon4AzKCuRhRo3N8LLViubQscGxxkOxjlMsUkKj\nLSYG10uKsF1AZGz01/wZVzZjcVMLDr6plhq1kYgdJeWLGqSr2snFkpry9wl5Gsa0\nLQIDAQAB\n-----END PUBLIC KEY-----')
                self.client_secret = 'THE_WINGS_AGENT'


        def validate_server(self):
                self.con.send('VALIDATE_SERVER\n')
                server_secret = self.con.recv(1024).strip()
                server_secret = self.server_pub.encrypt(server_secret, 32)[0]
                if server_secret == 'THE_WINGS_SCANNER':
                        return True
                else:
                        return False

        def validate_client(self):
                self.con.send('VALIDATE_CLIENT\n')
                self.con.send(self.client_secret + '\n')
                response = self.con.recv(1024)
                if response == 'OK':
                        return True
                else:
                        return False

        def send_log(self, log_content, log_name):
                self.con.send(log_content.strip() + '\n')
                self.con.send('END\n')
                self.con.send(log_name.strip() + '\n')


        def finish(self):
                self.con.send('FIN\n')
                self.con.close()

myAgent = Agent('10.0.0.97', 9696)
if myAgent.validate_server():
        if myAgent.validate_client():
                #writeCVE()
                data = open('CVE.txt','r').read()
                myAgent.send_log(data, 'CVE')
                data = open('rootkit.bin','r').read()
                myAgent.send_log(data, 'rootkit')
                myAgent.finish()
