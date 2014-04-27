#
# run.py
# Run measurements with captures and compute results
#
# This file distributes under: The MIT License (MIT)
#
# Copyright (c) 2014 Nicolas Canceill
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from os import listdir as ls
from os import system as x
from shutil import move as mv
from time import sleep
import dpkt
from atlas import *
from tools import Measurement as M
from tools import pkstats

# Config
dn='nicolas.nlnetlabs.nl'
out='/tmp/tmp.pcap'
outdir='/home/nicolas/Documents/'
perms='perms.sh'
cap='tshark -i p1p2 -f "port 53" -p -F libpcap -w '
amp='&>/dev/null&'

# Run measurement
def m(nprob,subd,rrtype,do=True,ppi=True):
	m_(probes_WW(nprob),subd,rrtype,do=do,ppi=ppi)

def m_(probes,subd,rrtype,do=True,ppi=True):
	measures=[]
	# Launch capture
	print 'Launching capture...'
	x(cap+out+amp)
	sleep(30) # sleep 30 seconds
	print 'Capture running'
	# Launch measurements
	thed=dns(dn,rrtype.upper(),do=do,prepend_probe_id=ppi)
	if subd is not None:
		thed=dns(subd+'.'+dn,rrtype.upper(),do=do,prepend_probe_id=ppi)
	thep=probes
	them=atlas.create(thed,thep)
	measures+=[them['measurements'][0]]
	print 'Measurement launched'
	# Wait for results
	print 'Waiting for results...'
	sleep(5*60) # sleep 5 minutes
	chkct=0
	chk=list(measures)
	while len(chk)>0:
		for mid in chk:
			if atlas.measurement(mid).next()['status']['id']>2:
				chk.remove(mid)
		if chkct<5:
			sleep(60) # sleep 1 minute
		else:
			sleep(10) # sleep 10 seconds
		chkct+=1
		print str(len(measures)-len(chk))+' measurement(s) done'
	print 'Measurement done: '+str(measures[0])
	# Stop capture
	print 'Stopping capture...'
	x('kill $(pidof tshark)')
	sleep(30)
	x(outdir+perms)
	# Get results
	if subd is None:
		subd='apex'
	f=outdir+subd+'-'+rrtype.lower()+'-'+str(measures[0])+'.pcap'
	mv(out,f)
	print 'Measurements done'

def all(subd,rrtype,ppi=True,do=True):
	l=500
	up=[p['id'] for p in atlas.probe() if p['status']==1]
	_,msms=lsmsm(subd,rrtype)
	for msm in msms:
		for pid in M(msm).pids():
			try:
				up.remove(pid)
			except ValueError:
				pass
	while len(up)>0:
		print str(len(up))+' probes left'
		pids=up[:l]
		probes={'requested':len(pids),
			'type':'probes',
			'value':str(pids)[1:-1]}
		m_(probes,subd,rrtype,do=do,ppi=ppi)
		up=up[l:]
	print 'All done'

def lsmsm(subd,rrtype):
	ps_all=[]
	msm=[]
	bad=0
	if subd is None:
		subd='nicolas'
	for fn in ls(outdir):
		if not fn.startswith(subd+'-'+rrtype.lower()):
			continue
		fo=open(outdir+fn,'r')
		print 'Opening '+fn+'...'
		fps=dpkt.pcap.Reader(fo)
		for _,pkt in fps:
			try: # Rule out bad packets
				ipkt=dpkt.ethernet.Ethernet(pkt).data
				p={
					'src':ipkt.src,
					'dst':ipkt.dst,
					'udp':ipkt.p==17,
					'dns':dpkt.dns.DNS(ipkt.data.data)
					}
				t=p['dns'].qd[0].name.lower()
				if (
					subd=='nicolas' and t.endswith(dn)
					) or t.endswith(subd+'.'+dn):
					ps_all+=[p]
			except (IndexError,
				AttributeError,
				dpkt.UnpackError,dpkt.NeedData):
				bad+=1
		msm+=[int(fn.split('-')[2].split('.')[0])]
		print 'Closing '+fn+'...'
		fo.close()
	if bad>0:
		print str(bad)+' bad packets'
	return ps_all,set(msm)

def r(subd,rrtype,
	pkts=True,ppi=True,
	histResol=None,
	histResol_=None,
	histAD=None,
	histSF=None):
	if subd is None:
		subd='nicolas'
	# Get capture results
	print 'Parsing capture(s)...'
	ps,msm=lsmsm(subd,rrtype)
	if len(ps)<1:
		print 'No packet captured'
		return
	print str(len(ps))+' packets captured'
	# Get measures results
	ms=M(*msm)
	if ppi:
		pids=[str(i) for i in ms.pids()]
		ps_=[p for p in ps
			if str(p['dns'].qd[0].name).startswith(tuple(pids))]
	else:
		ps_=[p for p in ps
			if str(p['dns'].qd[0].name).startswith(subd)]
	# Print stats
	v=None
	if pkts:
		print 'Capture stats to target'
		v=pkstats(ps_,ppi=ppi,of=histResol,of_=histResol_)
		print '|'+'_'*47+'|'
	print 'Measurements stats'
	ms.allstats(thev=v,of=histAD,of_=histSF)
	print '|'+'_'*47+'|'
	if pkts:
		print 'All capture stats'
		pkstats(ps,ppi=ppi)
		print '|'+'_'*47+'|'

