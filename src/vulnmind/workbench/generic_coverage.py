"""Target-bound offline evaluation; no application names or built-in answers."""
from pathlib import Path
from urllib.parse import urlsplit
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field


class TargetBinding(BaseModel):
    model_config=ConfigDict(extra='forbid')
    origin:str
    repository:str
    source_snapshot:str=Field(pattern=r'^[0-9a-f]{64}$')


class RootRule(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str=Field(min_length=1,max_length=150)
    eligible:bool
    method:str
    path:str
    parameter:str=''
    kinds:list[str]=Field(min_length=1,max_length=20)
    behaviors:list[str]=Field(default_factory=list,max_length=20)


class Truth(BaseModel):
    model_config=ConfigDict(extra='forbid')
    schema_version:Literal['coverage-truth-2']
    target:TargetBinding
    roots:list[RootRule]=Field(min_length=1,max_length=1000)


def build_report(truth,result,label,*,config=None):
    truth=Truth.model_validate(truth)
    cfg=config or {};target=truth.target
    if (cfg.get('origin')!=target.origin or result.get('origin')!=target.origin
        or not cfg.get('repository') or Path(cfg['repository']).resolve()!=Path(target.repository).resolve()
        or result.get('source_snapshot')!=target.source_snapshot):
        raise ValueError('评估基准与任务的目标、仓库或源码版本不匹配')
    roots={r.id:r for r in truth.roots}
    if len(roots)!=len(truth.roots): raise ValueError('评估根因 ID 重复')
    candidates=set();behaviors=set()
    for o in result.get('observations',[]):
        if o.get('verdict') not in {'candidate','verified_behavior'}: continue
        u=urlsplit(o.get('url',''))
        if u.scheme+'://'+u.netloc!=target.origin: continue
        for r in roots.values():
            if (u.path==r.path and o.get('method')==r.method and o.get('parameter','')==r.parameter
                and o.get('kind') in r.kinds and (not r.behaviors or o.get('behavior') in r.behaviors)):
                candidates.add(r.id)
                if o['verdict']=='verified_behavior': behaviors.add(r.id)
    eligible={r.id for r in roots.values() if r.eligible}
    entries=[dict(root_cause_id=r.id,challenge_key=r.id,mode='anon' if r.eligible else 'needs_context',note='用户提供的独立基准') for r in roots.values()]
    missing=lambda ids:[dict(root=i,mode=['eligible' if roots[i].eligible else 'needs_context'],challenges=[i],note='尚无独立漏洞确认') for i in sorted(ids)]
    report=dict(label=label,job_id=result.get('job_id'),status=result.get('status'),requests_used=result.get('requests_used'),stop_reason=result.get('stop_reason'),
        evaluation_status='operator_supplied_target_bound_truth',denominators=dict(dynamic=len(roots),eligible=len(eligible),static=0),
        covered=dict(dynamic=[],eligible=[],confirmed=[],candidates=sorted(candidates),behavior=sorted(behaviors)),
        coverage=dict(overall_dynamic=0.0,eligible_dynamic=0.0 if eligible else None),
        candidate_coverage=dict(overall=len(candidates)/len(roots),eligible=len(candidates & eligible)/len(eligible) if eligible else None),
        targets=dict(overall_gt_50=False,eligible_ge_70=False),missing=dict(eligible=missing(eligible),dynamic_other=missing(set(roots)-eligible)))
    return report,entries,set()
