"""Offline boundary experiment on fixed OWASP source bytes; does not change the database."""
import json
from pathlib import Path
from vulnmind.knowledge.chunking import KnowledgeDocument,chunk_document

def candidate(text, size=1000, overlap=100):
    spans=[]
    start=0
    while start < len(text):
        end=min(start+size,len(text))
        if end < len(text):
            lower=start+size//2
            split=text.rfind('\n\n', lower, end)
            if split<lower: split=text.rfind('\n',lower,end)
            if split<lower: split=text.rfind(' ',lower,end)
            if split>=lower: end=split+1
        spans.append((start,end))
        if end==len(text): break
        start=max(start+1,end-overlap)
    return spans

def breaks_word(text, pos):
    return 0<pos<len(text) and text[pos-1].isalnum() and text[pos].isalnum()

def main():
    root=Path(__file__).resolve().parents[1]/'knowledge/corpora'
    docs=[]
    for folder in ('owasp_cheatsheets_757270a','owasp_expansion_757270a'):
        docs.extend(json.loads((root/folder/'corpus.json').read_text(encoding='utf-8')))
    stats={'fixed':{'chunks':0,'end_boundaries':0,'word_breaks':0},'candidate':{'chunks':0,'end_boundaries':0,'word_breaks':0}}
    for doc in docs:
        text=doc['content']
        existing=chunk_document(KnowledgeDocument(document_id='benchmark',content=text,source=doc['source_url']))
        plans={'fixed':[(c.start_offset,c.end_offset) for c in existing], 'candidate':candidate(text)}
        for name,spans in plans.items():
            stats[name]['chunks']+=len(spans)
            for _,end in spans:
                if end<len(text):
                    stats[name]['end_boundaries']+=1
                    stats[name]['word_breaks']+=breaks_word(text,end)
    print(json.dumps({'documents':len(docs),'stats':stats,'limitations':'Only end-boundary word splitting is counted; code fences, start boundaries, retrieval quality, citation accuracy and answer quality are not evaluated. Candidate not deployed.'}))
if __name__=='__main__':main()
