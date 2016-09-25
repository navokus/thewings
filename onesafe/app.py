#!/usr/bin/python

from flask import *
import json
import os
import time, datetime
from threading import Thread

from checkcert import docheckcert
from nikto import donikto
from fierce import dofierce
from w3af import dow3af

app = Flask(__name__)
JOB = {}


@app.route("/")
@app.route("/index")
def appindex():
	return render_template('index.html')

getfiles = lambda path: [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
getdirs = lambda path: [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]

def getpath(host):
	protocol, url = _parsehost(host)
	url = url.replace('/', '-').replace('\\', '-').replace('.', '_')
	path = "scan/%s_%s" % (protocol, url)
	return path


def _parsehost(host):
	if host.startswith('http://'):
		return 'http', host[7:]
	if host.startswith('https://'):
		return 'https', host[8:]
	return None, None


def _docheckcert(fn, host):
	global JOB
	try:
		data = docheckcert(host)
		mark = "F"
		if data['endpoints'][0].has_key('grade'):
			mark = data['endpoints'][0]['grade']
		data = json.dumps(data)
		open(fn, 'wb').write(data + "\n" + mark)
		print "[+] Check cert\n\thost : %s\n\tpath : %s" % (host, fn)
	except:
		print "[x] Error in check cert\n\thost : %s\n\tpath : %s" % (host, fn)
	del JOB[host]['cert']
	if len(JOB[host])==0: del JOB[host]

def _donikto(fn, host):
	global JOB
	try:
		donikto(fn, host)
		if os.path.exists(fn):
			data = open(fn, 'rb').read().strip()
			while data.count('"id":0')>0:
				data = data.replace('"id":0', '"id":')
			data = data[:-4] + "]}"
			data = json.loads(data)
			per = len(data['vulnerabilities']) / 3
			ar = ["A", "A-", "B", "B-", "C", "C-", "D", "D-", "F"]
			if per>=len(ar): per = len(ar)-1
			open(fn, 'wb').write(json.dumps(data) + "\n" + ar[per])
			print "[+] Nikto\n\thost : %s\n\tpath : %s" % (host, fn)
		else:
			print "[x] Error in nikto\n\thost : %s\n\tpath : %s" % (host, fn)
	except:
		print "[x] Error in nikto\n\thost : %s\n\tpath : %s" % (host, fn)
	del JOB[host]['nikto']
	if len(JOB[host])==0: del JOB[host]

def _dofierce(fn, host):
	global JOB
	try:
		pro, url = _parsehost(host)
		if url.find('/')>=0:
			url = url[:url.find('/')]
		url = url.strip()
		data, per = dofierce(url)
		mark = "A"
		if per>0: mark = "D"
		open(fn, 'wb').write(json.dumps(data) + "\n" + mark)
		print "[+] Fierce\n\thost : %s\n\tpath : %s" % (host, fn)
	except:
		print "[x] Error in fierce\n\thost : %s\n\tpath : %s" % (host, fn)
	del JOB[host]['fierce']
	if len(JOB[host])==0: del JOB[host]

def _dow3af(fn, host):
	global JOB
	try:
		dow3af(fn, host)
		#open(fn, 'wb').write(json.dumps(data) + "\n" + mark)
		print "[+] W3af\n\thost : %s\n\tpath : %s" % (host, fn)
	except:
		print "[x] Error in w3af\n\thost : %s\n\tpath : %s" % (host, fn)
	del JOB[host]['w3af']
	if len(JOB[host])==0: del JOB[host]



def dohost(host):
	global JOB
	JOB[host] = {	'cert' : 'doing',
					'nikto' : 'doing',
					'fierce' : 'doing'
					,'w3af' : 'doing'
				}
	protocol, url = _parsehost(host)
	path = getpath(host)

	#tls
	if not os.path.exists(path): os.mkdir(path)
	fn = str(int(time.time()))
	if protocol == 'https':
		if not os.path.exists("%s/cert" % path): os.mkdir("%s/cert" % path)
		Thread(target=_docheckcert, args=("%s/cert/%s.log" % (path, fn), host,)).start()
	else:
		del JOB[host]['cert']
	
	#nikto
	if not os.path.exists("%s/nikto" % path): os.mkdir("%s/nikto" % path)
	Thread(target=_donikto, args=("%s/nikto/%s.log" % (path, fn), host,)).start()
	
	#fierce
	if not os.path.exists("%s/fierce" % path): os.mkdir("%s/fierce" % path)
	Thread(target=_dofierce, args=("%s/fierce/%s.log" % (path, fn), host,)).start()
	
	#w3af
	if not os.path.exists("%s/w3af" % path): os.mkdir("%s/w3af" % path)
	Thread(target=_dow3af, args=("%s/w3af/%s.log" % (path, fn), host,)).start()
	#-----


@app.route("/scan", methods=['GET', 'POST'])
def appscan():
	print JOB
	curhost = request.cookies.get('host')
	#request.form POST
	#request.args GET
	if request.method == 'POST':
		host = request.form.get('host')
		if host != None:
			if curhost != None and host != curhost and curhost in JOB:
				return render_template('scan.html', msg="Your current scan is still running!")
			if host not in JOB:
				dohost(host)
				resp = make_response(render_template('scan.html', msg="Running scan!"))
				resp.set_cookie('host', host)
				return resp
			else:
				resp = make_response(render_template('scan.html', msg="Switch to exists scanning!"))
				resp.set_cookie('host', host)
				return resp
	return render_template('scan.html', msg="Nothing!")

def getlog(host, t1, ind):
	path = getpath(host)
	files = getfiles(path + "/" + t1)
	files.sort()
	log = files[ind]
	return  open("%s/%s/%s" % (path, t1, log), 'rb').read()


@app.route("/scan/current", methods=['GET'])
def appscancurrent():
	global JOB
	curhost = request.cookies.get('host')
	d = request.args.get('type')
	#cert / nikto / fiere /w3af
	if curhost != None and d != None:
		if (curhost not in JOB) or (curhost in JOB and d not in JOB[curhost]):
			dd = getlog(curhost, d, -1).split('\n')
			if len(dd)>1:
				return "OK" + dd[1]
			else:
				return "OKA"
		else:
			return "Running"
	return "Running"

@app.route("/scan/fierce", methods=['GET'])
def appscanfierce():
	global JOB
	host = request.args.get('host')
	ind = request.args.get('id')
	print host, ind
	if host != None and ind != None:
		d = getlog(host, "fierce", int(ind)).split('\n')
		data = json.loads(d[0])
		m = 'A'
		if len(d)>=2:
			m = d[1]
		#ips = data['ips']
		#ns = data['ns']
		return render_template('fierce.html', host=host, mark=m, data=data)
	return render_template('fierce.html', host=host)


@app.route("/scan/cert", methods=['GET'])
def appscancert():
	global JOB
	host = request.args.get('host')
	ind = request.args.get('id')
	print host, ind
	if host != None and ind != None:
		d = getlog(host, "cert", int(ind)).split('\n')
		data = json.loads(d[0])
		m = 'A'
		if len(d)>=2:
			m = d[1]
		#ips = data['ips']
		#ns = data['ns']
		return render_template('cert.html', host=host, mark=m, data=data)
	return render_template('cert.html', host=host)


@app.route("/scan/nikto", methods=['GET'])
def appscannikto():
	global JOB
	host = request.args.get('host')
	ind = request.args.get('id')
	print host, ind
	if host != None and ind != None:
		d = getlog(host, "nikto", int(ind)).split('\n')
		data = d[0].strip()
		if data.endswith('},],}'):
			while data.count('"id":0')>0: data = data.replace('"id":0', '"id":')
			data = data[:-4] + "]}"
		data = json.loads(data)
		m = 'A'
		if len(d)>=2: m = d[1]
		#ips = data['ips']
		#ns = data['ns']
		return render_template('nikto.html', host=host, mark=m, data=data)
	return render_template('nikto.html', host=host)



@app.route("/scan/w3af", methods=['GET'])
def appscanw3af():
	global JOB
	host = request.args.get('host')
	ind = request.args.get('id')
	print host, ind
	if host != None and ind != None:
		m = 'A'
		return render_template('w3af.html', host=host, mark=m, id=ind)
	return render_template('w3af.html', host=host)

@app.route("/scan/w3af/raw", methods=['GET'])
def appscanw3afraw():
	global JOB
	host = request.args.get('host')
	ind = request.args.get('id')
	print host, ind
	if host != None and ind != None:
		d = getlog(host, "w3af", int(ind))
		return d, 200, {'Content-Type': 'text/plain; charset=utf-8'}
	return ""


@app.route("/scanhistory", methods=['GET', 'POST'])
def appscanhistory():
	'''
	if request.method == 'POST':
		host = request.form.get('host')
		if host != None:
			if curhost != None and host != curhost and curhost in JOB:
				return render_template('scan.html', msg="Your current scan is still running!")
			if host not in JOB:
				dohost(host)
				resp = make_response(render_template('scan.html', msg="Running scan!"))
				resp.set_cookie('host', host)
				return resp
			else:
				resp = make_response(render_template('scan.html', msg="Switch to exists scanning!"))
				resp.set_cookie('host', host)
				return resp
	abcd.xyz/bbbb
	abcd_xyz

	'''
	ds = getdirs('scan')
	hosts = []
	for d in ds:
		prot = d[:d.find("_")]
		d = d[d.find("_")+1:]
		d = d.replace("_", ".").replace("-", "/")
		hosts.append((prot, "%s://%s" % (prot, d)))
	return render_template('scanhistory.html', hosts=hosts)

@app.route("/agenthistory", methods=['GET', 'POST'])
def appagenthistory():
	'''
	if request.method == 'POST':
		host = request.form.get('host')
		if host != None:
			if curhost != None and host != curhost and curhost in JOB:
				return render_template('scan.html', msg="Your current scan is still running!")
			if host not in JOB:
				dohost(host)
				resp = make_response(render_template('scan.html', msg="Running scan!"))
				resp.set_cookie('host', host)
				return resp
			else:
				resp = make_response(render_template('scan.html', msg="Switch to exists scanning!"))
				resp.set_cookie('host', host)
				return resp
	abcd.xyz/bbbb
	abcd_xyz

	'''
	ds = getdirs('monitor')
	return render_template('agenthistory.html', ds=ds)


@app.route("/agent/cve", methods=['GET'])
def appagentcve():
	ip = request.args.get('ip')
	ind = request.args.get('id')
	if ip != None and ind != None:
		return render_template('cve.html', ip=ip, id=ind)

@app.route("/agent/cve/raw", methods=['GET'])
def appagentcveraw():
	global JOB
	ip = request.args.get('ip')
	ind = request.args.get('id')
	if ip != None and ind != None:
		ind = int(ind)
		files = getfiles("monitor/%s" % ip)
		f = []
		for fo in files:
			if fo.find("CVE")>=0:
				f.append(fo)
		f.sort()
		d = open("monitor/%s/%s" % (ip, f[ind])).read()
		return d, 200, {'Content-Type': 'text/plain; charset=utf-8'}
	return ""



@app.route("/agent/rootkit", methods=['GET'])
def appagentrootkit():
	ip = request.args.get('ip')
	ind = request.args.get('id')
	if ip != None and ind != None:
		return render_template('rootkit.html', ip=ip, id=ind)

@app.route("/agent/rootkit/raw", methods=['GET'])
def appagentrootkitraw():
	global JOB
	ip = request.args.get('ip')
	ind = request.args.get('id')
	if ip != None and ind != None:
		ind = int(ind)
		files = getfiles("monitor/%s" % ip)
		f = []
		for fo in files:
			if fo.find("rootkit")>=0:
				f.append(fo)
		f.sort()
		d = open("monitor/%s/%s" % (ip, f[ind])).read()
		return d, 200, {'Content-Type': 'text/plain; charset=utf-8'}
	return ""



app.run(host="0.0.0.0", debug=True)