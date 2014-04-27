#
# tools.py
# Compute and print results from measurements and capture files
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

import re
from atlas import *
from base64 import decodestring as d64
from socket import inet_ntop as getip,AF_INET as i4,AF_INET6 as i6
from dpkt.dns import *

#
# Static tools
#

# Check for non-local IP

l0='(^127\.0\.0\.1)'
l1='(^10\.)'
l2='(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)'
l3='(^192\.168\.)'
lan=l0+'|'+l1+'|'+l2+'|'+l3

def isWide(ip):
	return re.match(lan,ip) is None

def widen(ips):
	return [ip for ip in ips if isWide(ip)]

# Parse answer buffer

def pisAD(pkt):
	return pkt.op&DNS_AD>0

def isAD(abuf):
	return pisAD(DNS(d64(abuf)))

def pisDO(pkt):
	return len(pkt.ar)>0

def phasSig(pkt):
	return len([x for x in pkt.an if x.type==46])>0

def hasSig(abuf):
	return phasSig(DNS(d64(abuf)))

def ptango(pkt):
	q=pkt.qd
	if len(q)<1:
		return None
	return q[0].name

def tango(abuf):
	return ptango(DNS(d64(abuf)))

def ppid(pkt):
	t=ptango(pkt)
	if t is None:
		return None
	pid=t.split('.')[0]
	if re.match('[0-9]',pid):
		return pid
	return None

# Parse measurement results

def chk(r,ids,ispid=False):
	for id in ids:
		if r['msm_id']==id and not ispid:
			return True
		if r['prb_id']==id and ispid:
			return True
	return False

def flatset(res):
	ofthejedi=[]
	for r in res:
		if 'resultset' in r:
			for x in r['resultset']:
				r_=dict(r)
				r_['result']=x
				del r_['resultset']
		else:
			r_=r
		if 'result' in r_ and 'result' in r_['result']:
			r_.update(r_['result'])
		if 'dst_addr' not in r_ and 'dst_addr' in r_['result']:
			r_['dst_addr']=r_['result']['dst_addr']
		if 'result' not in r_ or 'abuf' in r_['result']:
			ofthejedi+=[r_]
	return ofthejedi

# Printing stats

h='{}[{:0=4.0%}] [{:0=4.0%}]'
h_='{} {:.1%}{:.1%}{:.1%}'
h0='|\t{}\t|\t{}\t|'
h1='| {}\t| {}\t| {}\t| {}\t|'

# Parsing capture

def pkstats(pkts,ppi=True,of=None,of_=None):
	que=[p for p in pkts if p['dns'].qr==DNS_Q and p['udp']]
	q0=len(que)
	res=[p for p in pkts if p['dns'].qr==DNS_R and p['udp']]
	r0=len(res)
	if q0>0: # Check for queries
		qp=0
		if ppi:
			pids=list(set([ppid(p['dns']) for p in que
				if ppid(p['dns']) is not None]))
			qp=len(que)/float(len(pids))
		v={p['src']:[] for p in que}
		v1=len(set(v.keys()))
		if ppi and of is not None:
			print 'Counting probes\' resolvers...'
			for p in que:
				v[p['src']]+=[int(ppid(p['dns']))]
			ofo=open(of,'w')
			ofo.write('\\addplot[fill=black] coordinates {\n')
			ofo_=None
			if of_ is not None:
				ofo_=open(of_,'w')
				ofo_.write('\\addplot[fill=black] coordinates {\n')
			theh={}
			top=0
			thev={x:len(set(y)) for x,y in v.iteritems()}
			for n in sorted(thev.values(),reverse=True):
				top+=1
				if top<40:
					print top,
					theres_=[x for x,y in thev.iteritems()
						if y==n]
					for theres in theres_:
						try:
							print ' '+getip(i4,theres)
						except ValueError:
							print ' '+getip(i6,theres)
				if ofo_ is not None and n>1:
					ofo_.write('('+str(top)+','+str(n)+')\n')
				try:
					theh[str(n)]+=1
				except KeyError:
					theh[str(n)]=1
			for pc,rc in theh.iteritems():
				ofo.write('('+pc+','+str(rc)+')\n')
			ofo.write('};')
			ofo.close()
			if ofo_ is not None:
				ofo_.write('};')
				ofo_.close()
			print 'Wrote resolvers histogram at '+of
		do=[p['src'] for p in que if pisDO(p['dns'])]
		do0=len(do)/float(q0)
		do1=len(set(do))/float(v1)
		dop0=0
		if ppi:
			dop=set([ppid(p['dns']) for p in que
				if ppid(p['dns']) is not None and pisDO(p['dns'])])
			dop0=len(dop)/float(len(pids))
		print h1.format('Q/Pr','Resol','Uniq','DO [Uniq] [/Pr]')
		print h1.format('%.2f'%qp,q0,v1,
			h.format('%.0f%%'%(do0*100)+' ',do1,dop0))
	if r0<1:
		return # No answer was sent
	rp=0
	if ppi:
		pids=list(set([ppid(p['dns']) for p in res
			if ppid(p['dns']) is not None]))
		pids_={pid:len([p for p in res
				if ppid(p['dns'])==pid
			]) for pid in pids}
		rp=len(res)/float(len(pids))
	v_=[p['dst'] for p in res]
	v_1=len(set(v_))
	as_=[p['dst'] for p in res if phasSig(p['dns'])]
	as0=len(as_)/float(r0)
	as1=len(set(as_))/float(v_1)
	asp0=0
	if ppi:
		asp=set([ppid(p['dns']) for p in res
			if ppid(p['dns']) is not None and  phasSig(p['dns'])])
		asp0=len(asp)/float(len(pids))
	print h1.format('A/Pr','Resol','Uniq','Sig [Uniq] [/Pr]')
	print h1.format('%.2f'%rp,r0,v_1,h.format('%.0f%%'%(as0*100)+' ',as1,asp0))
	return v

#
# Measurement collection
#

class Measurement:
	def __init__(self,*ids):
		self.i=[]
		self.r=[]
		for id in ids:
			self.add(id)

	def add(self,*ids):
		print 'Parsing results from '+str(*ids)
		for id in ids:
			self.i+=[id]
			self.r+=flatset(atlas.result(id).next())

	def pids(self):
		return [x['prb_id'] for x in self.r]

	def froms(self,ids,pid=False):
		return [x['from'] for x in self.r if chk(x,ids,ispid=pid)]

	def targets(self,ids,pid=False):
		return list(set([tango(x['result']['abuf']) for x in self.r
				if chk(x,ids,ispid=pid) and 'result' in x]))

	def resolvers(self,ids,pid=False):
		return [x['dst_addr'] for x in self.r if chk(x,ids,ispid=pid)]

	def answers(self,ids,pid=False):
		return [[x['dst_addr'],x['result']] for x in self.r
				if chk(x,ids,ispid=pid) and 'result' in x]

	def stats(self,ids,pid=False,thev=None,of=None,of_=None):
		v=self.resolvers(ids,pid=pid)
		v0=len(v)
		k=widen(v)
		k0=len(k)
		k1=len(set(k))
		a=[x[0] for x in self.answers(ids,pid=pid)]
		a0=len(a)
		an=[x[0] for x in self.answers(ids,pid=pid)
			if x[1]['ANCOUNT']>0]
		an0=len(an)
		ar=[x[0] for x in self.answers(ids,pid=pid)
			if x[1]['ARCOUNT']>0]
		ar0=len(ar)
		if a0<1:
			return # No answer
		a_=widen(a)
		a1=len(a_)
		ad=[x[0] for x in self.answers(ids,pid=pid)
				if isAD(x[1]['abuf'])
				and not hasSig(x[1]['abuf'])]
		ad0=len(ad)/float(a0)
		as_=[x[0] for x in self.answers(ids,pid=pid)
				if hasSig(x[1]['abuf'])
				and not isAD(x[1]['abuf'])]
		as0=len(as_)/float(a0)
		asd=[x[0] for x in self.answers(ids,pid=pid)
				if isAD(x[1]['abuf'])
				and hasSig(x[1]['abuf'])]
		asd0=len(asd)/float(a0)
		if thev is not None and of is not None:
			print 'Counting probes\' ADs...'
			ofo=open(of,'w')
			ofo.write('\\addplot[fill=green] coordinates {\n')
			ofo_=None
			if of_ is not None:
				ofo_=open(of_,'w')
				ofo_.write('\\addplot[fill=green] coordinates {\n')
			theh={}
			theh_={}
			chkps=[]
			for theps_ in sorted(thev.values()):
				theps=[x for x in theps_ if x not in chkps]
				chkps+=theps
				flps=1.
				if len(theps)>0:
					flps=float(len(theps))
				ra=len([x for x in self.answers(theps,pid=True)
					if isAD(x[1]['abuf'])]
					)/flps
				naz=len([x for x in self.answers(theps,pid=True)
					if DNS(d64(x[1]['abuf'])).rcode==2]
					)/flps
				try:
					theh[str(len(theps))]+=ra
				except KeyError:
					theh[str(len(theps))]=ra
				if ofo_ is not None:
					try:
						theh_[str(len(theps))]+=naz
					except KeyError:
						theh_[str(len(theps))]=naz
			for pc,rc in theh.iteritems():
				ofo.write('('+pc+','+str(rc)+')\n')
			ofo.write('};')
			ofo.close()
			if ofo_ is not None:
				for pc,nc in theh_.iteritems():
					ofo_.write('('+pc+','+str(nc)+')\n')
				ofo_.write('};')
				ofo_.close()
			print 'Wrote ADs histogram at '+of
		print h0.format('Resol','Rep:AN:AR:ADs AD S AD+S')
		print h0.format(v0,
				h_.format('%d:%d:%d:%d'%(
					a0,an0,ar0,len(ad)+len(asd)),
			ad0,as0,asd0))
		if a1<1:
			return # Answers from local IPs only
		a2=len(set(a_))
		ad_=widen(ad)
		ad1=len(ad_)/float(a1)
		ad2=len(set(ad_))/float(a2)
		as__=widen(as_)
		as1=len(as__)/float(a1)
		as2=len(set(as__))/float(a2)
		asd_=widen(asd)
		asd1=len(asd_)/float(a1)
		asd2=len(set(asd))/float(a2)
		print h1.format('Know','Uniq','Know AD S ADS','Uniq AD S ADS')
		print h1.format(k0,k1,
			h_.format(a1,ad1,as1,asd1),
			h_.format(a2,ad2,as2,asd2))
		sp=set(self.pids())
		#WARNING: the following lines may break stuff
		ap=[pi for pi in sp
			if len([re for re in self.r
				if chk(re,[pi],ispid=True)
				and 'result' in re
				and re['result']['ANCOUNT']>0])>0]
		ap0=len(ap)/float(len(sp))
		adp=[pi for pi in sp
			if len([re for re in self.r
				if chk(re,[pi],ispid=True)
				and 'result' in re
				and isAD(re['result']['abuf'])
				and not hasSig(re['result']['abuf'])])>0]
		adp0=len(adp)/float(len(sp))
		asp=[pi for pi in sp
			if len([re for re in self.r
				if chk(re,[pi],ispid=True)
				and 'result' in re
				and not isAD(re['result']['abuf'])
				and hasSig(re['result']['abuf'])])>0]
		asp0=len(asp)/float(len(sp))
		asdp=[pi for pi in sp
			if len([re for re in self.r
				if chk(re,[pi],ispid=True)
				and 'result' in re
				and isAD(re['result']['abuf'])
				and hasSig(re['result']['abuf'])])>0]
		asdp0=len(asdp)/float(len(sp))
		print h0.format('Prob','Ans  AD   Sig  AD+S')
		print h0.format(len(sp),
			('{}:{:0=4.2%} '*4).format(
				len(ap),ap0,len(adp),adp0,'',asp0,len(asdp),asdp0))
		nan=[x for x in self.r
			if 'result' in x
			and x['result']['ANCOUNT']<1]
		ers={DNS(d64(x['result']['abuf'])).rcode:0 for x in nan}
		ers_=dict(ers)
		for x in nan:
			ers[DNS(d64(x['result']['abuf'])).rcode]+=1
			if x['result']['ARCOUNT']<1:
				ers_[DNS(d64(x['result']['abuf'])).rcode]+=1
		print ers
		print ers_
		print set([DNS(d64(x['result']['abuf'])).qd[0].type for x in nan
			if DNS(d64(x['result']['abuf'])).rcode==0])

	def allstats(self,thev=None,of=None,of_=None):
		self.stats(self.i,thev=thev,of=of,of_=of_)
