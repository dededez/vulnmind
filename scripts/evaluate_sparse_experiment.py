"""Read-only exploratory sparse-retrieval comparison; not a production retriever."""
import json
import re
import time
from pathlib import Path
from sqlalchemy import create_engine, text
from vulnmind.config import Settings

STOP = frozenset('a an and are as at be by can do for from how in is of on or should the to what which with'.split())
SQL = text('''SELECT d.title FROM knowledge_chunks c JOIN knowledge_documents d ON d.id=c.document_id
WHERE c.tsvector @@ CASE WHEN :mode = 'all' THEN plainto_tsquery('pg_catalog.simple', :query)
ELSE to_tsquery('pg_catalog.simple', :terms) END
ORDER BY ts_rank(c.tsvector, CASE WHEN :mode = 'all' THEN plainto_tsquery('pg_catalog.simple', :query)
ELSE to_tsquery('pg_catalog.simple', :terms) END) DESC, c.document_id, c.chunk_index, c.id LIMIT 10''')
MATCH_SQL = text('''SELECT title FROM (SELECT d.title, c.id, c.document_id, c.chunk_index,
 (SELECT count(*) FROM unnest(string_to_array(:words, '|')) w
  WHERE c.tsvector @@ plainto_tsquery('pg_catalog.simple', w)) AS matched
 FROM knowledge_chunks c JOIN knowledge_documents d ON d.id = c.document_id
 WHERE c.tsvector @@ to_tsquery('pg_catalog.simple', :terms)) s
 WHERE matched >= 3 ORDER BY matched DESC, document_id, chunk_index, id LIMIT 10''')

def main():
 root=Path(__file__).resolve().parents[1]
 train=json.loads((root/'evaluation/owasp_full_cases.json').read_text(encoding='utf-8'))
 hold=json.loads((root/'evaluation/knowledge_holdout_20261105.json').read_text(encoding='utf-8'))['cases']
 engine=create_engine(Settings().database_url)
 output=[]
 try:
  with engine.connect() as conn:
   conn.execute(text('SET TRANSACTION READ ONLY'))
   for group,cases in [('existing',train),('provisional_holdout',[c for c in hold if c['answerable']]),
                       ('unanswerable',[c for c in hold if not c['answerable']])]:
    for case in cases:
     words=list(dict.fromkeys(w for w in re.findall(r'[a-z0-9]+|[\u4e00-\u9fff]+',case['query'].lower()) if w not in STOP))[:24]
     terms=' | '.join(words) or 'vulnmind_unmatchable_token'
     row={'group':group,'query':case['query'],'expected_title':case.get('expected_title')}
     for mode in ('all','or_experiment','three_term_experiment'):
      start=time.perf_counter()
      if mode=='three_term_experiment':
       titles=list(conn.execute(MATCH_SQL, {'words':'|'.join(words) or 'vulnmind_unmatchable_token', 'terms':terms}).scalars())
      else:
       titles=list(conn.execute(SQL, {'mode':mode,'query':case['query'],'terms':terms}).scalars())
      row[mode]={'hit_at_5':case.get('expected_title') in titles[:5] if case.get('expected_title') else None,
                 'elapsed_ms':round((time.perf_counter()-start)*1000,2), 'top5_titles':titles[:5], 'returned':len(titles)}
     output.append(row)
 finally: engine.dispose()
 print(json.dumps({'note':'Read-only exploration; neither candidate is deployed. Three-term threshold was selected after seeing these results; labels are not independent expert annotations.', 'results':output},ensure_ascii=False))
if __name__=='__main__': main()
