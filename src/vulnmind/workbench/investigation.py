"""Bounded request plans and differential observations, independent of models."""
import hashlib
import json
import re
from urllib.parse import urlencode
from vulnmind.schemas import Target
from vulnmind.security.scope import check_target


def correlate(saved, imported, config, scope):
    routes=[]
    merged={(r['method'],r['path']):dict(r) for r in saved['routes']}
    for item in imported:
        key=(item['method'],item['path'])
        existing=merged.get(key,{})
        merged[key]={**existing,**{k:v for k,v in item.items() if v is not None},
            'file':item.get('file') or existing.get('file'),'handler':item.get('handler') or existing.get('handler'),
            'parameters':item['parameters'] or existing.get('parameters',[])}
    for item in merged.values():
        route=dict(item)
        path=config.get('path_prefix','').rstrip('/')+route['path']
        if any(c in path for c in '{}<>') or re.search(r'/:\w+|\*',path):
            route.update(mapping_status='needs_concrete_path',executable=False)
        else:
            url=config['origin']+path
            try:
                check_target(Target(type='web',locator=url),scope)
                from vulnmind.analysis.http_broker_worker import safe_path
                safe_path(path)
                route.update(url=url,executable=route['method']=='GET' or (route['method']=='POST' and config.get('allow_post',False)),
                    mapping_status='operator_bound' if config['binding_confirmed'] else 'unverified_deployment')
            except ValueError:
                route.update(mapping_status='out_of_scope',executable=False)
        route['id']=hashlib.sha256(json.dumps([route['method'],route['path']],sort_keys=True).encode()).hexdigest()[:16]
        route['source_link_verified']=bool(config['binding_confirmed'] and any(
            all(original.get(k)==route.get(k) for k in ('method','path','file','handler'))
            for original in saved['routes']))
        if config.get('pipeline_version',1)>=6 and set(route.get('signals',[])) & {'possible_state_change','unresolved_mount'}:
            route.update(executable=False,mapping_status='needs_state_or_mount_review')
        routes.append(route)
    return dict(routes=routes,source_snapshot=saved['digest'],deployment_version=config['deployment_version'],
                interpretation='operator_asserted_deployment_and_static_route_mapping_not_runtime_proof')


def actions_for(mapping):
    result=[]
    for route in mapping['routes']:
        if not route.get('executable'): continue
        for parameter in route.get('parameters',[])[:2]:
            if re.search('password|passwd|token|secret|cookie|authorization',parameter,re.I): continue
            for kind in ('reflection','template_expression','sql_error'):
                value=dict(route_id=route['id'],method=route['method'],url=route['url'],parameter=parameter,
                    parameters=route['parameters'],encoding=route.get('encoding','json'),kind=kind,
                    source=dict(file=route.get('file'),line=route.get('line'),handler=route.get('handler'),
                        signals=route.get('signals',[]),linked=route['source_link_verified']))
                value['id']=hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()[:20]
                result.append(value)
    # Prioritize source-supported hypotheses so short budgets cover useful checks.
    result.sort(key=lambda a: 0 if (a['kind']=='template_expression' and 'dynamic_template' in a['source']['signals']) or (a['kind']=='sql_error' and 'dynamic_sql' in a['source']['signals']) else 1)
    return result[:24]


def requests_for(action):
    # Two challenges plus a baseline, all exact requests visible before approval.
    values={'reflection':['vm_control_a82','vm_reflect_b19','vm_reflect_c31'],
            'template_expression':['vm_control_a82','{{731*19}}','{{823*23}}'],
            'sql_error':['vm_control_a82',"vm_probe'",'vm_control_b93']}[action['kind']]
    requests=[]
    for index,value in enumerate(values):
        fields={p:'vm_control_a82' for p in action['parameters']}
        fields[action['parameter']]=value
        body=''; url=action['url']; headers={'Accept':'application/json, text/html'}
        if action['method']=='GET': url+='?'+urlencode(fields)
        elif action['encoding']=='form':
            body=urlencode(fields); headers['Content-Type']='application/x-www-form-urlencoded'
        else:
            body=json.dumps(fields,ensure_ascii=True); headers['Content-Type']='application/json'
        requests.append(dict(method=action['method'],url=url,body=body,headers=headers,variant=index))
    return requests


def evaluate(action,responses):
    bodies=[r['body'] for r in responses]
    complete=all(200<=r['status_code']<300 and not r['truncated'] for r in responses)
    verdict='inconclusive'; detail='未取得足够信号，不能据此排除问题'; behavior=None
    if complete and action['kind']=='template_expression':
        a,b='13889','18929'
        matches=lambda text,value: bool(re.search(r'(?<![0-9])'+value+r'(?![0-9])',text))
        if (not matches(bodies[0],a) and not matches(bodies[0],b) and matches(bodies[1],a) and not matches(bodies[1],b)
                and matches(bodies[2],b) and not matches(bodies[2],a) and '{{731*19}}' not in bodies[1] and '{{823*23}}' not in bodies[2]):
            verdict='verified_behavior'; behavior='server_side_expression_evaluation'
            detail='两组不同算术输入得到各自预期值，基线未出现这些值；仅确认表达式求值行为，不推断代码执行能力'
    elif complete and action['kind']=='reflection':
        if ('vm_reflect_b19' in bodies[1] and 'vm_reflect_c31' in bodies[2]
                and all(marker not in bodies[0] for marker in ('vm_reflect_b19','vm_reflect_c31'))
                and 'vm_reflect_c31' not in bodies[1] and 'vm_reflect_b19' not in bodies[2]):
            verdict='candidate'; detail='两组标记均反射；不等于脚本执行或 XSS 已证实'
    elif action['kind']=='sql_error':
        signatures=('sqlstate[','you have an error in your sql syntax','syntax error at or near',
                    'unclosed quotation mark','sqlite_error','sqlite error','sqlite3.operationalerror',
                    'sequelize','e11000','mongodb','bson','unrecognized token','syntax error near')
        if not any(r['truncated'] for r in responses) and any(s in bodies[1].lower() and s not in bodies[0].lower() and s not in bodies[2].lower() for s in signatures):
            verdict='candidate'; detail='引号请求独有数据库错误特征；仍需确认因果和实际影响'
    if any(r['status_code'] in {401,403} for r in responses):
        verdict='inconclusive';behavior=None
        detail='认证或访问被拒绝；检查认证配置后新建任务，当前结果不作漏洞判断'
    return dict(action_id=action['id'],kind=action['kind'],url=action['url'],method=action['method'],parameter=action['parameter'],
        source=action['source'],verdict=verdict,behavior=behavior,detail=detail,
        response_hashes=[r['sha256'] for r in responses],statuses=[r['status_code'] for r in responses])
