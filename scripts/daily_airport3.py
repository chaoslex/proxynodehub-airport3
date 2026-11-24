#!/usr/bin/env python3
"""Discover public ProxyNodeHub-style feeds, convert candidates, Mihomo-test and publish a daily snapshot."""
import base64, concurrent.futures, datetime, json, os, re, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request
from pathlib import Path
import yaml, qrcode

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'site'
TOKEN = os.environ.get('GITHUB_TOKEN', '')
API = 'https://api.github.com'
HEADERS = {'User-Agent':'ProxyNodeHub-Airport3/1.0','Accept':'application/vnd.github+json'}
LOCAL_API_HEADERS = {'Authorization':'Bearer airport3-local','User-Agent':'Airport3-Mihomo-Probe/1.0'}
if TOKEN: HEADERS['Authorization'] = 'Bearer ' + TOKEN

def get(url, timeout=20, raw=False):
    req=urllib.request.Request(url, headers=({**HEADERS, 'Accept':'*/*'} if raw else (LOCAL_API_HEADERS if url.startswith('http://127.0.0.1:') else HEADERS)))
    with urllib.request.urlopen(req, timeout=timeout) as r: return r.read()
def github_json(url): return json.loads(get(url))
def raw_url(repo, branch, path): return f'https://raw.githubusercontent.com/{repo}/{urllib.parse.quote(branch,safe="")}/{urllib.parse.quote(path,safe="/")}'

def discover_files():
    # ProxyNodeHub's search vocabulary, plus its built-in known subscription map.
    since=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=14)).strftime('%Y-%m-%d')
    queries=['v2ray nodes','free proxy subscription','clash nodes','免费节点','v2ray 订阅','free v2ray','trojan nodes','sing-box subscription']
    repos={}
    for q in queries:
        try:
            params=urllib.parse.urlencode({'q':f'{q} pushed:>{since}','sort':'updated','order':'desc','per_page':20})
            for r in github_json(f'{API}/search/repositories?{params}').get('items',[]):
                if not r.get('fork') and r['full_name'].lower()!='chaoslex/proxynodehub-airport3': repos[r['full_name']]=r['default_branch']
        except Exception as e: print(f'query warning: {q}: {e}',flush=True)
    # Known feed locations shipped by ProxyNodeHub remain useful seeds when repo search misses them.
    known=json.loads((ROOT/'core/known_repos.json').read_text())['known_repos']
    feed_urls=[]
    seed_branches={}
    for entry in known:
        if entry.get('type','').lower()=='clash':
            path=entry['path']
            if entry.get('is_absolute_url') or path.startswith('http'):
                feed_urls.append(path)
            else:
                repo=entry['full_name']
                try:
                    branch=seed_branches.setdefault(repo, github_json(f'{API}/repos/{repo}').get('default_branch','main'))
                except Exception: branch='main'
                feed_urls.append(raw_url(repo,branch,path))
    # Discover likely Clash feeds from repository trees. Search reads public metadata only.
    files=list(dict.fromkeys(feed_urls))
    for name,branch in list(repos.items())[:120]:
        try:
            tree=github_json(f'{API}/repos/{name}/git/trees/{urllib.parse.quote(branch,safe="")}?recursive=1').get('tree',[])
            matches=[]
            for item in tree:
                p=item.get('path',''); low=p.lower()
                if item.get('type')!='blob' or not (low.endswith(('.yaml','.yml','.txt'))): continue
                base=low.rsplit('/',1)[-1]
                if any(x in base for x in ('clash','mihomo','sub')) or base in ('config.yaml','config.yml'):
                    if not any(x in low for x in ('readme','test','example','workflow','docker','package','lock')): matches.append(p)
            files.extend(raw_url(name,branch,p) for p in matches[:2])
        except Exception as e: print(f'tree warning {name}: {e}',flush=True)
    # bounded deduplicated fetch set: each observed feed is a candidate source, not a node cap.
    return list(dict.fromkeys(files))[:240]

def b64decode(s):
    s=''.join(s.split()); s += '='*((4-len(s)%4)%4)
    for fn in (base64.b64decode,base64.urlsafe_b64decode):
        try:
            b=fn(s.encode()); t=b.decode('utf-8','ignore')
            if t and ('://' in t or 'proxies:' in t or 'server:' in t): return t
        except Exception: pass
    return s

def uri_proxy(line):
    line=line.strip()
    try:
        if line.startswith('vmess://'):
            payload=line[8:].split('#')[0]; obj=json.loads(base64.urlsafe_b64decode(payload+'='*((4-len(payload)%4)%4)))
            p={'name':urllib.parse.unquote(line.split('#',1)[1]) if '#' in line else obj.get('ps','vmess'),'type':'vmess','server':obj.get('add'),'port':int(obj.get('port')),'uuid':obj.get('id'),'alterId':int(obj.get('aid',0) or 0),'cipher':obj.get('scy','auto'),'udp':True}
            net=obj.get('net','tcp'); tls=obj.get('tls','').lower()=='tls'
            if tls: p['tls']=True; p['servername']=obj.get('sni') or obj.get('host') or obj.get('add')
            if net=='ws': p.update({'network':'ws','ws-opts':{'path':obj.get('path') or '/', 'headers':{'Host':obj.get('host') or obj.get('add')}}})
            return p
        u=urllib.parse.urlsplit(line); scheme=u.scheme.lower(); q=urllib.parse.parse_qs(u.query); name=urllib.parse.unquote(u.fragment) or f'{scheme}-{u.hostname}-{u.port}'
        if not u.hostname or not u.port: return None
        if scheme=='vless':
            p={'name':name,'type':'vless','server':u.hostname,'port':u.port,'uuid':u.username,'udp':True,'network':q.get('type',['tcp'])[0]}
            sec=q.get('security',[''])[0]
            if sec in ('tls','reality'):
                p['tls']=True; p['servername']=q.get('sni',[u.hostname])[0]
            fp=q.get('fp',[''])[0]
            if fp: p['client-fingerprint']=fp
            if sec=='reality': p['reality-opts']={'public-key':q.get('pbk',[''])[0],'short-id':q.get('sid',[''])[0]}
            flow=q.get('flow',[''])[0]
            if flow: p['flow']=flow
            if p['network']=='ws': p['ws-opts']={'path':q.get('path',['/'])[0], 'headers':{'Host':q.get('host',[u.hostname])[0]}}
            elif p['network']=='grpc': p['grpc-opts']={'grpc-service-name':q.get('serviceName',[''])[0]}
            return p
        if scheme=='trojan':
            p={'name':name,'type':'trojan','server':u.hostname,'port':u.port,'password':urllib.parse.unquote(u.username or ''),'udp':True,'sni':q.get('sni',[u.hostname])[0]}
            if q.get('type',['tcp'])[0]=='ws': p['network']='ws'; p['ws-opts']={'path':q.get('path',['/'])[0],'headers':{'Host':q.get('host',[u.hostname])[0]}}
            return p
        if scheme=='ss':
            userinfo=u.netloc.rsplit('@',1)[0]
            try: dec=base64.urlsafe_b64decode(userinfo+'='*((4-len(userinfo)%4)%4)).decode()
            except Exception: dec=urllib.parse.unquote(userinfo)
            method,sep,pwd=dec.partition(':')
            if not sep: return None
            return {'name':name,'type':'ss','server':u.hostname,'port':u.port,'cipher':method,'password':pwd,'udp':True}
    except Exception: return None
    return None

def normalize_text(data):
    text=data.decode('utf-8','ignore').strip()
    if text.startswith(('proxies:','mixed-port:','port:')): return text
    if '://' not in text:
        dec=b64decode(text)
        if dec!=text: text=dec
    # URI list source
    proxies=[]
    for line in text.splitlines():
        if line.strip().startswith(('vmess://','vless://','trojan://','ss://')):
            p=uri_proxy(line)
            if p: proxies.append(p)
    if proxies: return yaml.safe_dump({'proxies':proxies},allow_unicode=True,sort_keys=False)
    return text

def valid_proxy(p):
    return isinstance(p,dict) and all(k in p for k in ('name','type','server','port')) and str(p.get('name','')).strip() and str(p.get('server','')).strip() and isinstance(p.get('port'),int) and 1<=p['port']<=65535

def validate_candidates(candidates, mihomo_bin):
    """Use Mihomo config validation to isolate unsupported/malformed candidate entries."""
    valid=[]
    def check(batch):
        cfg={'allow-lan':False,'mode':'rule','log-level':'error','proxies':batch,
             'proxy-groups':[{'name':'AIRPORT3-PROBE','type':'select','proxies':[p['name'] for p in batch]}],
             'rules':['MATCH,AIRPORT3-PROBE']}
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/'validate.yaml'; f.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
            r=subprocess.run([mihomo_bin,'-t','-f',str(f)],capture_output=True,text=True,timeout=20)
        if r.returncode==0:
            valid.extend(batch); return
        if len(batch)==1:
            print(f"Mihomo config rejected candidate {batch[0]['name']}: {(r.stderr or r.stdout)[-700:]}",flush=True); return
        mid=len(batch)//2; check(batch[:mid]); check(batch[mid:])
    # Start with a batch so errors can be bisected without losing the valid candidates.
    for i in range(0,len(candidates),100): check(candidates[i:i+100])
    return valid

def main():
    day=sys.argv[1]
    print(f'Discovering public feeds for {day}',flush=True)
    urls=discover_files(); print(f'Candidate feed URLs: {len(urls)}',flush=True)
    allp=[]; seen=set()
    def fetch_parse(url):
        try:
            data=get(url,timeout=20,raw=True)
            if len(data)>12_000_000: return []
            text=normalize_text(data)
            obj=yaml.safe_load(text)
            ps=obj.get('proxies',[]) if isinstance(obj,dict) else []
            return [p for p in ps if valid_proxy(p)]
        except Exception as e: print(f'feed skipped: {url[:130]} ({e})',flush=True); return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        for group in pool.map(fetch_parse,urls):
            for p in group:
                # use canonical config sans name for dedupe; distinct aliases kept once.
                key=json.dumps({k:v for k,v in p.items() if k!='name'},sort_keys=True,ensure_ascii=False)
                if key not in seen: seen.add(key); allp.append(p)
    if not allp: raise RuntimeError('No structurally valid Clash-compatible nodes discovered; refusing to publish empty output.')
    print(f'Unique candidate nodes: {len(allp)}',flush=True)
    # Preserve uniqueness while ensuring Mihomo's proxy names are unique.
    name_seen=set(); candidates=[]
    for i,p in enumerate(allp):
        p=dict(p); base=str(p['name']).strip()[:90] or f'node-{i+1}'; nm='A3-'+base; n=2
        while nm in name_seen: nm=f'A3-{base[:82]}-{n}'; n+=1
        name_seen.add(nm); p['name']=nm; candidates.append(p)
    candidates=validate_candidates(candidates,os.environ['MIHOMO_BIN'])
    if not candidates: raise RuntimeError('Mihomo rejected every candidate configuration; refusing to publish empty output.')
    print(f'Candidates accepted by Mihomo config validation: {len(candidates)}',flush=True)
    # Run one Mihomo process with the complete valid candidate set; unresponsive nodes are failures.
    api_port=19090
    cfg={'allow-lan':False,'mode':'rule','log-level':'error','external-controller':f'127.0.0.1:{api_port}','secret':'airport3-local','proxies':candidates,'proxy-groups':[{'name':'AIRPORT3-PROBE','type':'select','proxies':[p['name'] for p in candidates]}],'rules':['MATCH,AIRPORT3-PROBE']}
    with tempfile.TemporaryDirectory() as td:
        conf=Path(td)/'probe.yaml'; conf.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
        proc=subprocess.Popen([os.environ['MIHOMO_BIN'],'-d',td,'-f',str(conf)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        try:
            base=f'http://127.0.0.1:{api_port}'
            for _ in range(60):
                if proc.poll() is not None: raise RuntimeError('Mihomo exited before probe API was ready: '+(proc.stderr.read()[-3000:] if proc.stderr else ''))
                try: get(base+'/version',timeout=1); break
                except Exception: time.sleep(.5)
            else: raise RuntimeError('Mihomo API did not become ready')
            def probe(p):
                try:
                    # 5-second timeout is encoded in this endpoint query.
                    q=urllib.parse.urlencode({'url':'https://www.gstatic.com/generate_204','timeout':5000})
                    url=base+'/proxies/'+urllib.parse.quote(p['name'],safe='')+'/delay?'+q
                    r=json.loads(get(url,timeout=7))
                    ms=int(r.get('delay',0)); return (p,ms) if ms>0 else (None,None)
                except Exception: return (None,None)
            passed=[]
            with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
                for p,ms in pool.map(probe,candidates):
                    if p is not None: passed.append((p,ms))
            passed.sort(key=lambda x:x[1]); selected=passed[:50]
            if not selected: raise RuntimeError(f'Mihomo found no passing nodes out of {len(candidates)} candidates; refusing to publish empty output.')
            # Fresh date-specific Clash YAML with tested nodes only.
            final={'mixed-port':7890,'allow-lan':False,'mode':'rule','log-level':'info','proxies':[x[0] for x in selected], 'proxy-groups':[{'name':'PROXY','type':'select','proxies':[x[0]['name'] for x in selected]}], 'rules':['MATCH,PROXY']}
            OUT.mkdir(parents=True,exist_ok=True)
            filename=f'alexfree-{day}-机场3.yaml'; f=OUT/filename
            f.write_text('# Cloud Mihomo test; not a phone-side reachability guarantee.\n'+yaml.safe_dump(final,allow_unicode=True,sort_keys=False),encoding='utf-8')
            # Validate generated file with the same Mihomo binary in config-check mode.
            v=subprocess.run([os.environ['MIHOMO_BIN'],'-t','-f',str(f)],capture_output=True,text=True,timeout=20)
            if v.returncode: raise RuntimeError('Generated YAML failed Mihomo validation: '+v.stderr[-3000:])
            # QR points at dated Pages artifact, not a transient workflow file.
            page=f'https://chaoslex.github.io/proxynodehub-airport3/{urllib.parse.quote(filename)}'
            qrcode.make(page).save(OUT/f'{filename[:-4]}-qr.png')
            (OUT/'index.html').write_text(f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>机场3订阅</title><body style="font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem"><h1>机场3 · ProxyNodeHub 节点订阅</h1><p>今日文件：<a href="{filename}">{filename}</a></p><p>通过 Mihomo 5 秒 generate_204 检测：{len(selected)} / {len(candidates)} 个候选。按实测延迟升序保留最快最多50个。</p><p><a href="{filename[:-4]}-qr.png">订阅二维码</a></p><p>测试来自 GitHub 托管运行环境，不代表手机网络可达；免费节点可能随时失效。</p></body></html>''',encoding='utf-8')
            print(json.dumps({'date':day,'feed_urls':len(urls),'candidate_nodes':len(candidates),'passed':len(passed),'selected':len(selected),'min_ms':selected[0][1],'max_ms':selected[-1][1],'yaml':filename,'url':page,'qr':f'{filename[:-4]}-qr.png'},ensure_ascii=False))
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
if __name__=='__main__': main()
