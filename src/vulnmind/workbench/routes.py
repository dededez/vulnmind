"""Bounded static route indexing. Never imports or executes target code."""
import ast
import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit
from vulnmind.security.scope import check_target
from vulnmind.schemas import Target


def snapshot(root, scope, *, extended=False):
    root=Path(root).resolve(strict=True)
    check_target(Target(type='repository',locator=str(root)),scope)
    files, routes, skipped, total = {}, [], 0, 0
    excluded={'.git','.venv','venv','node_modules','__pycache__','.devtools'}
    for directory,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in excluded and not Path(directory,d).is_symlink() and not Path(directory,d).is_junction())
        for name in sorted(names):
            path=Path(directory,name)
            if path.suffix!='.py':
                continue
            if len(files)>=200:
                skipped+=1
                continue
            if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root):
                skipped+=1
                continue
            check_target(Target(type='repository',locator=str(path.parent)),scope)
            with path.open('rb') as stream:
                raw=stream.read(1_000_001)
            total+=len(raw)
            if len(raw)>1_000_000 or total>8_000_000:
                raise ValueError('repository route indexing exceeds bounded input size')
            relative=path.relative_to(root).as_posix()
            files[relative]=hashlib.sha256(raw).hexdigest()
            try:
                tree=ast.parse(raw.decode('utf-8-sig'))
            except (SyntaxError,UnicodeError):
                skipped+=1
                continue
            for node in ast.walk(tree):
                if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    continue
                params=set(a.arg for a in node.args.args if a.arg not in {'self','request','response'})
                signals=[]
                for item in ast.walk(node):
                    if isinstance(item,ast.Subscript) and isinstance(item.slice,ast.Constant) and isinstance(item.slice.value,str):
                        if isinstance(item.value,ast.Attribute) and item.value.attr in {'json','args','form'}:
                            params.add(item.slice.value)
                    if isinstance(item,ast.Call):
                        called=item.func.attr if isinstance(item.func,ast.Attribute) else item.func.id if isinstance(item.func,ast.Name) else ''
                        if called=='get' and isinstance(item.func,ast.Attribute) and isinstance(item.func.value,ast.Attribute) and item.func.value.attr in {'args','form','json'} and item.args and isinstance(item.args[0],ast.Constant) and isinstance(item.args[0].value,str):
                            params.add(item.args[0].value)
                        if called in {'render_template_string','from_string'} and item.args and not isinstance(item.args[0],ast.Constant):
                            signals.append('dynamic_template')
                        if called in {'execute','executemany'} and item.args and isinstance(item.args[0],(ast.JoinedStr,ast.BinOp)):
                            signals.append('dynamic_sql')
                        if extended:
                            name=ast.unparse(item.func)
                            if name.startswith(('requests.','httpx.','urllib.request.')): signals.append('outbound_request')
                            if called in {'open','read_text','read_bytes','send_file'}: signals.append('file_access')
                            if name.startswith(('subprocess.','os.system','os.popen')): signals.append('process_execution')
                            if name in {'pickle.loads','pickle.load','yaml.load'}: signals.append('deserialization')
                            if called in {'fromstring','parse'} and any(p in name for p in ('xml','etree','ElementTree')): signals.append('xml_parse')
                            if called=='redirect': signals.append('redirect')
                for decorator in node.decorator_list:
                    if not isinstance(decorator,ast.Call) or not isinstance(decorator.func,ast.Attribute) or not decorator.args:
                        continue
                    name=decorator.func.attr.lower()
                    if name not in {'get','post','route','api_route'} or not isinstance(decorator.args[0],ast.Constant) or not isinstance(decorator.args[0].value,str):
                        continue
                    methods=[name.upper()] if name in {'get','post'} else ['GET']
                    for kw in decorator.keywords:
                        if kw.arg=='methods' and isinstance(kw.value,(ast.List,ast.Tuple)):
                            methods=[v.value.upper() for v in kw.value.elts if isinstance(v,ast.Constant) and isinstance(v.value,str)]
                    for method in methods:
                        routes.append(dict(method=method,path=decorator.args[0].value,file=relative,line=node.lineno,
                            end_line=node.end_lineno,handler=node.name,parameters=sorted(params)[:6],signals=sorted(set(signals)),
                            source_hash=files[relative],basis='static_decorator',mapping_status='candidate'))
    digest=hashlib.sha256(repr(sorted(files.items())).encode()).hexdigest()
    return dict(root=str(root),files=files,digest=digest,routes=routes[:200],skipped=skipped,truncated=len(routes)>200)


def verify_snapshot(saved):
    root=Path(saved['root'])
    for name,expected in saved['files'].items():
        path=root/name
        if path.is_symlink() or path.is_junction() or not path.resolve().is_relative_to(root):
            raise ValueError('repository snapshot path changed')
        cursor=path.parent
        while cursor!=root:
            if cursor.is_symlink() or cursor.is_junction():
                raise ValueError('repository directory changed')
            cursor=cursor.parent
        with path.open('rb') as stream:
            raw=stream.read(1_000_001)
        if hashlib.sha256(raw).hexdigest()!=expected:
            raise ValueError('repository changed; create a new versioned task')


def imported_routes(document, origin):
    """Read explicit mappings, OpenAPI or HAR; discard headers/cookies/bodies."""
    result=[]
    if isinstance(document,list):
        source=document
    elif 'openapi' in document:
        source=[]
        for path,item in document.get('paths',{}).items():
            for method,operation in item.items():
                if method.lower() not in {'get','post'}:
                    continue
                params=[p['name'] for p in operation.get('parameters',[]) if p.get('in')=='query' and 'name' in p]
                content=operation.get('requestBody',{}).get('content',{})
                media=next((m for m in ('application/json','application/x-www-form-urlencoded') if m in content),None)
                if media:
                    params+=list(content[media].get('schema',{}).get('properties',{}))
                source.append(dict(path=path,method=method.upper(),parameters=params,encoding='form' if media=='application/x-www-form-urlencoded' else 'json'))
    elif 'log' in document:
        source=[]
        for entry in document['log'].get('entries',[])[:500]:
            req=entry.get('request',{}); parts=urlsplit(req.get('url',''))
            if f'{parts.scheme}://{parts.netloc}'!=origin:
                continue
            params=[p.get('name','') for p in req.get('queryString',[])]
            post=req.get('postData',{})
            params += [p.get('name','') for p in post.get('params',[])]
            if post.get('mimeType','').startswith('application/json'):
                import json
                try:
                    body=json.loads(post.get('text','{}'))
                    if isinstance(body,dict): params+=list(body)
                except ValueError: pass
            source.append(dict(path=parts.path,method=req.get('method','GET'),parameters=params,
                encoding='form' if post.get('mimeType')=='application/x-www-form-urlencoded' else 'json'))
    else:
        raise ValueError('expected route list, OpenAPI or HAR')
    for item in source[:200]:
        if item.get('method','GET').upper() not in {'GET','POST'}: continue
        path=item.get('path','')
        if not isinstance(path,str) or not path.startswith('/') or len(path)>1000: raise ValueError('invalid route path')
        params=item.get('parameters',[])
        if not isinstance(params,list) or any(not isinstance(p,str) or not p or len(p)>64 for p in params): raise ValueError('invalid parameter names')
        result.append(dict(path=path,method=item.get('method','GET').upper(),parameters=sorted(set(params))[:6],
            file=item.get('file'),handler=item.get('handler'),encoding=item.get('encoding','json'),basis='operator_import',mapping_status='candidate'))
    return result
