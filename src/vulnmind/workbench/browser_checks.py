"""Browser hypotheses from discovered query parameters, with causal controls."""
import hashlib
import json
from urllib.parse import urlencode


def actions(mapping):
    result=[]
    for route in mapping['routes']:
        if not route.get('executable') or route['method']!='GET': continue
        for parameter in route.get('parameters',[])[:2]:
            if any(s in parameter.lower() for s in ('password','token','secret','cookie')): continue
            seed=hashlib.sha256((route['url']+parameter).encode()).hexdigest()[:16]
            marker='vm-'+seed
            fields={p:'vm-control' for p in route['parameters']}
            fields[parameter]='vm-control';baseline=route['url']+'?'+urlencode(fields)
            fields[parameter]='<svg onload="alert(\''+marker+'\')">'
            url=route['url']+'?'+urlencode(fields)
            value=dict(kind='browser_xss',category='xss',method='GET',url=url,baseline_url=baseline,marker=marker,
                parameter=parameter,parameters=route['parameters'],cost=120,detector_version='7.0.0',
                route_id=route['id'],source={'linked':route.get('source_link_verified',False),'signals':[]})
            value['id']=hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()[:20];result.append(value)
    return result[:12]
