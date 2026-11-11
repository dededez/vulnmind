"""Compare fixed versus structure-seeking boundaries on the same document subset.

Read-only PostgreSQL and local model. Not a full-corpus or independent benchmark.
"""
import json
import time
from pathlib import Path
import numpy as np
from huggingface_hub import snapshot_download
from sentence_transformers import SentenceTransformer
from sqlalchemy import create_engine,select,text
from sqlalchemy.orm import Session

from compare_chunk_boundaries import candidate
from vulnmind.config import Settings
from vulnmind.knowledge.embedding_batch import KEY, content_hash,vector_hash
from vulnmind.knowledge.model_fingerprint import MODEL,fingerprint,model_identity
from vulnmind.persistence.models import KnowledgeDocument, KnowledgeChunk


def main():
 root=Path(__file__).resolve().parents[1]
 cases=json.loads((root/'evaluation/knowledge_holdout_positive_20261105.json').read_text(encoding='utf-8'))
 folders=('owasp_cheatsheets_757270a','owasp_expansion_757270a')
 docs={x['title']:x for f in folders for x in json.loads((root/'knowledge/corpora'/f/'corpus.json').read_text(encoding='utf-8'))}
 titles=sorted({x['expected_title'] for x in cases})
 manifest=fingerprint(); info=model_identity(manifest)
 model=SentenceTransformer(snapshot_download(MODEL,revision=info['revision'],local_files_only=True),device='cpu',trust_remote_code=False,local_files_only=True)
 old=[];new=[];texts=[]
 e=create_engine(Settings().database_url)
 try:
  with Session(e) as s,s.begin():
   s.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
   for title in titles:
    document=s.scalar(select(KnowledgeDocument).where(KnowledgeDocument.title==title))
    if document is None: raise ValueError('required document missing')
    content=docs[title]['content']
    for c in s.scalars(select(KnowledgeChunk).where(KnowledgeChunk.document_id==document.id).order_by(KnowledgeChunk.chunk_index)):
     meta=c.metadata_ or {}; marker=meta.get(KEY,{})
     if c.embedding is None or any(marker.get(k)!=v for k,v in info.items()) or marker.get('document_version')!=document.version or marker.get('content_sha256')!=content_hash(c.content) or marker.get('vector_sha256')!=vector_hash(c.embedding):
      raise ValueError('baseline vector provenance mismatch')
     start,end=meta['start_offset'],meta['end_offset']
     if content[start:end]!=c.content: raise ValueError('source text and database chunk mismatch')
     old.append({'title':title,'start':start,'end':end,'vector':list(c.embedding)})
    for start,end in candidate(content):
     new.append({'title':title,'start':start,'end':end});texts.append(content[start:end])
 finally:e.dispose()
 began=time.perf_counter()
 new_vectors=model.encode(texts,batch_size=8,normalize_embeddings=True,show_progress_bar=False)
 query_vectors=model.encode([x['query'] for x in cases],prompt_name='query',normalize_embeddings=True,show_progress_bar=False)
 encode_seconds=round(time.perf_counter()-began,2)
 if fingerprint()!=manifest: raise ValueError('model files changed while encoding')
 # Re-normalize stored, rounded vectors before cosine ranking.
 old_vectors=np.asarray([x.pop('vector') for x in old],dtype=np.float32)
 old_vectors=old_vectors/np.linalg.norm(old_vectors,axis=1,keepdims=True)
 new_vectors=np.asarray(new_vectors,dtype=np.float32)
 results=[]
 for case,q in zip(cases,query_vectors):
  row={'query':case['query'],'expected_title':case['expected_title']}
  for name,chunks,vectors in [('fixed',old,old_vectors),('candidate',new,new_vectors)]:
   start=time.perf_counter();scores=vectors @ q
   ranked=np.argsort(-scores,kind='stable')[:5];elapsed=(time.perf_counter()-start)*1000
   selected=[chunks[int(i)] for i in ranked]
   row[name]={'document_hit_at_5':any(x['title']==case['expected_title'] for x in selected),
    'excerpt_hit_at_5':any(x['title']==case['expected_title'] and x['start']<=case['expected_start_offset'] and x['end']>=case['expected_end_offset'] for x in selected),
    'distinct_documents':len({x['title'] for x in selected}),'scoring_ms':round(elapsed,3)}
  results.append(row)
 print(json.dumps({'documents':len(titles),'cases':len(cases),'fixed_chunks':len(old),'candidate_chunks':len(new),
  'candidate_encoding_seconds':encode_seconds,'results':results,
  'limitations':'Same-agent, one excerpt per query; only selected OWASP documents, excluding other corpus; no FTS, code-fence, adversarial or answer correctness evaluation. Not deployed.'},ensure_ascii=False))
if __name__=='__main__':main()
