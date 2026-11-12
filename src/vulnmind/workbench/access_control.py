"""Explicit two-principal read-only authorization matrix, independent of URL names."""
import hashlib
import json
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator


class AccessCheck(BaseModel):
    model_config=ConfigDict(extra='forbid')
    credential_a:str=Field(min_length=1,max_length=64)
    credential_b:str=Field(min_length=1,max_length=64)
    resource_a:str=Field(min_length=1,max_length=2000)
    resource_b:str=Field(min_length=1,max_length=2000)
    identity_path:list[str]=Field(min_length=1,max_length=8)
    identity_a:str|int
    identity_b:str|int
    expected_policy:Literal['owner_only']
    ownership_basis:str=Field(min_length=10,max_length=500)

    @model_validator(mode='after')
    def distinct(self):
        if self.credential_a==self.credential_b or self.resource_a==self.resource_b or self.identity_a==self.identity_b:
            raise ValueError('two distinct identities, credentials and owned resources are required')
        return self


def actions(checks):
    result=[]
    for raw in checks:
        c=AccessCheck.model_validate(raw).model_dump()
        action=dict(kind='auth_idor',category='broken_access_control',cost=6,method='GET',url=c['resource_a'],
            parameter='',parameters=[],encoding='json',source={'signals':[],'linked':False},
            detector_version='7.0.0',access_check=c)
        action['id']=hashlib.sha256(json.dumps(action,sort_keys=True).encode()).hexdigest()[:20]
        action['route_id']='operator-owned:'+action['id'];result.append(action)
    return result


def requests_for(action):
    c=action['access_check']
    # Owner baselines, cross access in both directions, then anonymous controls.
    matrix=[('a','a'),('b','b'),('a','b'),('b','a'),(None,'a'),(None,'b')]
    return [dict(method='GET',url=c['resource_'+resource],headers={'Accept':'application/json'},body='',variant=i,
        no_session=True,credential_override=c['credential_'+role] if role else None)
        for i,(role,resource) in enumerate(matrix)]


def evaluate(action,responses):
    c=action['access_check']
    def identity(r):
        if not 200<=r['status_code']<300 or r.get('truncated'): return None
        try:
            value=json.loads(r['body'])
            for key in c['identity_path']: value=value[key]
            return value if isinstance(value,(str,int)) and not isinstance(value,bool) else None
        except (ValueError,TypeError,KeyError): return None
    ids=[identity(r) for r in responses]
    behavior=None;detail='身份基线不完整，无法判断越权'
    if len(ids)==6 and ids[:2]==[c['identity_a'],c['identity_b']]:
        if ids[4]==c['identity_a'] or ids[5]==c['identity_b']:
            behavior='anonymous_private_resource_read';detail='声明为私有的资源可匿名读取；需独立核实访问策略与数据敏感性'
        elif ids[2]==c['identity_b'] or ids[3]==c['identity_a']:
            behavior='cross_account_read';detail='两个资源归属基线匹配；交叉身份读取到对方资源，匿名对照未读取到资源。归属与私有策略来自操作者声明，保留为候选'
        else: detail='本人基线成功，本次交叉与匿名请求未读取到对应资源'
    return dict(action_id=action['id'],kind=action['kind'],category=action['category'],url=action['url'],method='GET',parameter='',
        verdict='candidate' if behavior else 'inconclusive',behavior=behavior,detail=detail,
        detector_version='7.0.0',policy_basis='operator_declared_owner_only',
        response_hashes=[r['sha256'] for r in responses],statuses=[r['status_code'] for r in responses])
