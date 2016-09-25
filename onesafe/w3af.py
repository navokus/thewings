from bs4 import BeautifulSoup
import requests
from easyprocess import Proc
import os


def getcookie(url, user, pwd):
	s = requests.Session()
	res = s.get(url)
	print res.headers

	data = res.text
	html = BeautifulSoup(data, 'lxml')
	form = html.find('form')

	fields = {}
	for inp in form.findAll('input'):
		if inp['type'] in ('submit', 'image') and not inp.has_key('name'):
			continue

		if inp['type'] in ('text', 'hidden', 'password', 'submit', 'image'):
			value = ''
			if inp.has_key('value'):
				value = inp['value']
			input_name = inp.get('name').lower()
			if ('login' in input_name or 'user' in input_name) and 'token' not in input_name:
				value = user
			if ('pass' in input_name or 'pwd' in input_name) and 'token' not in input_name:
				value = pwd
			fields[inp['name']] = value
	met = form.get('method').lower()
	if met == 'post':
		res = s.post(url, data=fields)
		print res.headers
		data = res.text
	else:
		data = s.get(url, params=fields)
	s.close()
	print fields
	c = s.cookies
	st = "Cookie: "
	for k in c.keys():
		st += "%s=%s; " % (k, c[k])
	open('cookie.txt','wb').write(st)
	return data

def dow3af(fn, host):
	st = '''

# -----------------------------------------------------------------------------------------------------------
#                                              W3AF AUDIT SCRIPT FOR WEB APPLICATION
# -----------------------------------------------------------------------------------------------------------
#Configure HTTP settings
http-settings
set timeout 10
#set headers_file cookie.txt
back

#Configure scanner global behaviors
misc-settings
set max_discovery_time 20
set fuzz_url_parts True
set fuzz_url_filenames True
back

plugins

#Configure entry point (CRAWLING) scanner
crawl web_spider
crawl config web_spider
set only_forward True
#set ignore_regex (?i)(logout|disconnect|signout|exit)+
set ignore_regex .*(logout|disconnect|signout|exit).*
back


#Configure reporting in order to generate an HTML report
output console

output config console
set verbose False
back

back
#Set target informations, do a cleanup and run the scan
target 
set target {0}
back

cleanup
start
exit'''.format(host)
	tmpfn =  fn[fn.rfind('/')+1:]
	open("/tmp/%s.w3af" % tmpfn, 'wb').write(st)
	#print 'w3af -s /tmp/%s.w3af | tee %s' % (tmpfn, fn)
	stdout=Proc("bash w3af.sh '/tmp/%s.w3af' '%s'" % (tmpfn, fn)).call(timeout=30).stdout
	os.remove("/tmp/%s.w3af" % tmpfn)
	return fn

#getcookie('http://192.168.200.1/DVWA/login.php', 'admin', 'password')

#print Proc('echo 123 ').call(timeout=10).stdout
#dow3af("dkm.txt", "https://risks.solutions/")
#print "DONE"