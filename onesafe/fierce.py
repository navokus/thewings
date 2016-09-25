
import subprocess
import re
import requests
import json

def parse(content):
	a = re.compile("(.+)\t+(.+)\t+(.+)\t+(.+)\t+(.+)\n")
	ar = []
	st = lambda x: x.strip('.\t')
	while True:
		b = a.search(content)
		if b != None:
			#b.groups()
			#('uit.edu.vn.\t\t', '5', 'IN', 'NS', 'ns100.vdc2.vn.')
			#('uit.edu.vn.\t\t', '5', 'IN', 'NS', 'ns99.vdc2.vn.')
			ar.append(map(st, b.groups()))
		else:
			break
		content = content[b.end():]
	return ar

def query(qr):
	p = subprocess.Popen(["dig", "+noall", "+answer"] + qr, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	st = p.stdout.read()
	p.wait()
	return st
	#return subprocess.check_output(["dig", "+noall", "+answer"] + qr)


def reverseip(query, source_type = "Web", top = 10, format = 'json'):
	'''
	        cloudflare_ips = ['199.27.128.0/21', '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                          '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
                          '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/12']
	'''
	url = "https://api.cognitive.microsoft.com/bing/v5.0/search?count=99999&q=ip:" + query
	user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36"
	headers = {"User-Agent": user_agent, "Ocp-Apim-Subscription-Key": "56bc821f305a422abfb8408c9b847747"}
	response_data = requests.get(url, headers=headers)
	d = json.loads(response_data.text)
	ar = []
	if 'webPages' in d:
		for e in d['webPages']['value']:
			k = e['displayUrl']
			if k.startswith('http://'): k = k[7:]
			if k.startswith('https://'): k = k[8:]
			if k.startswith('ftp://'): k = k[6:]
			ind = k.find('/')
			if ind>=0: k = k[:ind]
			if k not in ar: ar.append(k)
	return ar

def dofierce(host):
	output = {}
	ips = parse(query(["a", host]))
	#print ips
	output['ips'] = ips
	for a in ips:
		output['revip'] = []
		domains = reverseip(a[4])
		#array domain
		#print a[4]
		for dom in domains:
			output['revip'].append((a[4], dom))
			#revalidate?

	nss = parse(query(["ns", host]))
	#print nss
	output['ns'] = nss
	output['zone'] = {}
	c = 0
	for ns in nss:
		#print ns[4], "-"*50
		d = parse(query(["axfr", "@" + ns[4], host]))
		output['zone'][ns[4]] = d
		c += len(d)
	return output, c


#print dohostdns("trich.im")

