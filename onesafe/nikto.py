import subprocess

def donikto(fn, host):
	p = subprocess.Popen(["perl", "nikto/program/nikto.pl", "-Tuning=x4567890", "-Format=json", "-maxtime=60s", "-output=%s" % fn, "-host=%s" % host], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	st = p.stdout.read()
	p.wait()
