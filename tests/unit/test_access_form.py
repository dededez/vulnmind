"""Exercise actual form serialization without sending credentials or network requests."""
import subprocess
from pathlib import Path


def test_generic_identity_form_serializes_profiles_and_validates_before_saving():
    root=Path(__file__).resolve().parents[2]
    script=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const app=fs.readFileSync('src/vulnmind/workbench/static/app.js','utf8');
const html=fs.readFileSync('src/vulnmind/workbench/static/index.html','utf8');
assert(!html.includes('name="account"'));
assert(!html.includes('name="access_checks"'));
assert(!app.includes("api('/api/accounts'"));
let saved=[];
const ctx={URL,api:async(path,data)=>{saved.push({path,data});return {id:'profile-'+saved.length};}};
vm.createContext(ctx);
vm.runInContext(app.slice(app.indexOf('function accessCheckDraft('),app.lastIndexOf("$('#job-form').querySelector")),ctx);
const values={pipeline_version:'7',origin:'http://127.0.0.1:3000',access_identity_path:'document.owner',
 access_ownership:'Two private documents owned by separate controlled accounts',
 access_a_kind:'bearer',access_b_kind:'cookie',access_a_value:'secret-a',access_b_value:'session=secret-b',
 access_a_resource:'http://127.0.0.1:3000/documents/one',access_b_resource:'http://127.0.0.1:3000/documents/two',
 access_a_identity:'101',access_b_identity:'202',access_a_type:'number',access_b_type:'number'};
const form={querySelector:()=>({checked:true}),elements:{access_private:{checked:true}}};
(async()=>{
 const checks=await ctx.collectAccessChecks(form,k=>values[k]);
 assert.equal(saved.length,2);assert(saved.every(s=>s.path==='/api/credentials'));
 assert.equal(checks[0].credential_a,'profile-1');assert.equal(checks[0].identity_a,101);
 assert.equal(JSON.stringify(checks).includes('secret'),false);
 assert.equal(JSON.stringify(checks[0].identity_path),'["document","owner"]');
 saved=[];values.access_b_resource='http://other.invalid/resource';
 await assert.rejects(()=>ctx.collectAccessChecks(form,k=>values[k]));assert.equal(saved.length,0);
 values.access_b_resource='http://127.0.0.1:3000/documents/two';form.elements.access_private.checked=false;
 await assert.rejects(()=>ctx.collectAccessChecks(form,k=>values[k]));assert.equal(saved.length,0);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
    result=subprocess.run(['node','-e',script],cwd=root,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
