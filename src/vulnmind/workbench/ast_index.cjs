'use strict';
// The only executable dependency is a pinned, hash-checked workspace compiler.
const ts=require(process.argv[2]), path=require('path').posix;
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>input+=c);
process.stdin.on('end',()=>{
 const files=JSON.parse(input), units=new Map(), routes=[], clients=[], issues=[];
 const walk=(node,fn)=>{fn(node);ts.forEachChild(node,c=>walk(c,fn));};
 const literal=n=>n && (ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n)) ? n.text : null;
 const mod=(f,s)=>{const b=path.normalize(path.join(path.dirname(f),s));return [b,b+'.ts',b+'.js',b+'/index.ts',b+'/index.js'].find(k=>Object.hasOwn(files,k));};
 for(const [name,text] of Object.entries(files)){
  const sf=ts.createSourceFile(name,text,ts.ScriptTarget.Latest,true), imports=new Map(), symbols=new Map();
  walk(sf,n=>{
   if(ts.isImportDeclaration(n)&&n.importClause){
    const dest=mod(name,literal(n.moduleSpecifier)||'');if(!dest)return;
    if(n.importClause.name)imports.set(n.importClause.name.text,[dest,'default']);
    const bindings=n.importClause.namedBindings;
    if(bindings&&ts.isNamedImports(bindings))for(const e of bindings.elements)imports.set(e.name.text,[dest,(e.propertyName||e.name).text]);
    if(bindings&&ts.isNamespaceImport(bindings))imports.set(bindings.name.text,[dest,'*']);
   }
   if(ts.isFunctionDeclaration(n)&&n.name){symbols.set(n.name.text,n);if(n.modifiers?.some(m=>m.kind===ts.SyntaxKind.DefaultKeyword))symbols.set('default',n);}
   if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&n.initializer)symbols.set(n.name.text,n.initializer);
   if(ts.isExportAssignment(n))symbols.set('default',n.expression);
  });units.set(name,{sf,imports,symbols});
 }
 const resolve=(file,node)=>{
  const u=units.get(file);let binding;
  if(ts.isIdentifier(node)){binding=u.imports.get(node.text);if(!binding&&u.symbols.has(node.text))return [file,u.symbols.get(node.text),node.text];}
  if(ts.isPropertyAccessExpression(node)&&ts.isIdentifier(node.expression)){binding=u.imports.get(node.expression.text);if(binding?.[1]==='*')binding=[binding[0],node.name.text];else binding=null;}
  if(binding){const v=units.get(binding[0]);return v?.symbols.has(binding[1])?[binding[0],v.symbols.get(binding[1]),binding[1]]:null;}
  return null;
 };
 const routerBinding=(file,node,depth=0)=>{
  if(depth>4)return null;
  const r=resolve(file,node);if(!r)return null;
  if(ts.isCallExpression(r[1])&&/(^|\.)Router$/.test(r[1].expression.getText(units.get(r[0]).sf)))return r;
  if(ts.isIdentifier(r[1]))return routerBinding(r[0],r[1],depth+1);
  return null;
 };
 for(const [file,u] of units){
  const mounts=new Map();
  // Client URLs are commonly built as hostServer + '/rest/...' or template
  // literals; concatenate the static parts and keep only the path portion.
  const urlText=n=>{
   if(!n)return null;
   if(ts.isParenthesizedExpression(n))return urlText(n.expression);
   if(ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n))return n.text;
   if(ts.isTemplateExpression(n))return n.head.text+n.templateSpans.map(s=>'{'+s.expression.getText(u.sf)+'}'+s.literal.text).join('');
   if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken){
    const l=urlText(n.left),r=urlText(n.right);return (l===null&&r===null)?null:(l||'')+(r||'');
   }
   return null;
  };
  walk(u.sf,n=>{if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='use'&&literal(n.arguments[0])!==null){
   for(const a of n.arguments.slice(1))if(ts.isIdentifier(a)){
    const resolved=routerBinding(file,a);if(!resolved)continue;
    if(resolved[0]!==file)mounts.set(resolved[0],literal(n.arguments[0]));
    else mounts.set(file+':'+a.text,literal(n.arguments[0]));
   }
  }});
  walk(u.sf,n=>{
   if(!ts.isCallExpression(n)||!ts.isPropertyAccessExpression(n.expression))return;
   const method=n.expression.name.text.toLowerCase(), receiver=n.expression.expression.getText(u.sf), route=literal(n.arguments[0]);
   if(method==='use'&&receiver==='app'&&route?.startsWith('/')&&n.arguments.slice(1).some(a=>ts.isCallExpression(a)&&/(^|\.)(static|serveStatic|serveIndex)$/.test(a.expression.getText(u.sf)))){
    routes.push({method:'GET',path:route,file,line:u.sf.getLineAndCharacterOfPosition(n.getStart()).line+1,handler:'static_mount',handler_file:file,parameters:[],parameter_specs:[],signals:['static_directory'],encoding:'json',basis:'typescript_ast_literal',mapping_status:'candidate'});
   }
   if(!['get','post','put','patch','delete','head'].includes(method))return;
   if(route===null||!route.startsWith('/')){
    const built=urlText(n.arguments[0]);
    let path='';
    if(built){
     let text=built;
     if(/^[a-z]+:\/\//i.test(text)){try{text=new URL(text).pathname}catch(e){}}
     else if(!text.startsWith('/')){const i=text.indexOf('/');text=i>=0?text.slice(i):'';}
     path=text.split('?')[0]||'';
    }
    if(path.startsWith('/')&&/http|client/i.test(receiver))clients.push({method:method.toUpperCase(),path,file,line:u.sf.getLineAndCharacterOfPosition(n.getStart()).line+1});
    return;
   }
   if(!/^(app|router|\w*Router)$/.test(receiver)){
    if(/http|client/i.test(receiver))clients.push({method:method.toUpperCase(),path:route,file,line:u.sf.getLineAndCharacterOfPosition(n.getStart()).line+1});
    return;
   }
   let handler=[file,n,'inline'];
   for(const arg of n.arguments.slice(1))walk(arg,c=>{if(ts.isCallExpression(c)){const r=resolve(file,c.expression);if(r)handler=r;}else if(ts.isIdentifier(c)){const r=resolve(file,c);if(r)handler=r;}});
   const [hf,body,hn]=handler, sf=units.get(hf).sf, parameters=[],signals=new Set(),requestFields=new Map();
   walk(body,c=>{if(ts.isParameter(c)&&ts.isObjectBindingPattern(c.name))for(const e of c.name.elements){const field=(e.propertyName||e.name).getText(sf);if(['query','body','params','headers'].includes(field))requestFields.set(e.name.getText(sf),field);}});
   walk(body,c=>{
    let base,key;
    if(ts.isPropertyAccessExpression(c)){base=c.expression;key=c.name.text;}
    if(ts.isElementAccessExpression(c)){base=c.expression;key=literal(c.argumentExpression);}
    if(base&&key&&ts.isPropertyAccessExpression(base)&&/^req(uest)?$/.test(base.expression.getText(sf))&&['query','params','body','headers'].includes(base.name.text))parameters.push({name:key,location:{query:'query',params:'path',body:'json',headers:'header'}[base.name.text]});
    if(base&&key&&ts.isIdentifier(base)&&requestFields.has(base.text))parameters.push({name:key,location:{query:'query',params:'path',body:'json',headers:'header'}[requestFields.get(base.text)]});
    if(ts.isCallExpression(c)){
     const name=c.expression.getText(sf),arg=c.arguments[0];
     if(/\.query$/.test(name)&&arg&&(ts.isTemplateExpression(arg)||ts.isBinaryExpression(arg)))signals.add('dynamic_sql');
     if(/\.(save|update|destroy|create|insert|remove|deleteOne|updateOne)$/.test(name))signals.add('possible_state_change');
     if(/\.(readFile|readFileSync|sendFile|download)$/.test(name))signals.add('file_access');
     if(/\.redirect$/.test(name))signals.add('redirect');
     if(/\b(eval|exec|execSync)$/.test(name))signals.add('process_execution');
    }
    if(ts.isPropertyAssignment(c)&&c.name.getText(sf).replace(/['"]/g,'')==='$where')signals.add('dynamic_nosql');
   });
   const params=[...new Map(parameters.map(p=>[p.location+':'+p.name,p])).values()];
   routes.push({method:method.toUpperCase(),path:(mounts.get(file+':'+receiver)||'')+route,file,line:u.sf.getLineAndCharacterOfPosition(n.getStart()).line+1,
     handler:hn,handler_file:hf,parameters:params.filter(p=>p.location==='query'||p.location==='json').map(p=>p.name).slice(0,6),
     parameter_specs:params,signals:[...signals],encoding:'json',basis:'typescript_ast_literal',mapping_status:'candidate'});
  });
  for(const [child,prefix] of mounts)if(!child.includes(':'))issues.push({mount_file:child,prefix});
 }
 for(const r of routes){const m=issues.filter(i=>i.mount_file===r.file);if(m.length===1)r.path=m[0].prefix+r.path;else if(m.length>1)r.mount_ambiguous=true;}
 process.stdout.write(JSON.stringify({routes,client_endpoints:clients,parser_version:ts.version,limitations:['dynamic paths and complex re-exports require explicit mapping','AST signals are not taint proofs']}));
});
