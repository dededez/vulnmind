"""Back up local PostgreSQL, append reviewed tool knowledge, index new skills.

No migration, credential rewriting, corpus replacement or embedding deletion.
Embedding backfill is a separate resumable operation.
"""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine,text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from vulnmind.config import Settings
from vulnmind.integrations.hexstrike.catalog import ROOT
from vulnmind.knowledge.skills import SkillLoader,SkillIndexer


def main():
    root=Path(__file__).resolve().parents[1];settings=Settings();url=make_url(settings.database_url)
    if url.get_backend_name()!='postgresql' or url.host not in {'localhost','127.0.0.1','::1'}:
        raise ValueError('only the configured local development database is supported')
    engine=create_engine(url)
    with engine.connect() as conn:
        original={str(i):hashlib.sha256(content.encode()).hexdigest() for i,content in conn.execute(text('select id,content from knowledge_chunks'))}
        head=conn.execute(text('select version_num from alembic_version')).scalar_one()
    backup=root/'.devtools/backups'/('before-hexstrike-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.dump')
    backup.parent.mkdir(parents=True,exist_ok=True)
    if backup.exists(): raise ValueError('backup already exists')
    pg=root/'.devtools/pgsql/bin';flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
    result=subprocess.run([str(pg/'pg_dump.exe'),'-h',url.host,'-p',str(url.port or 5432),'-U',url.username,
                           '-d',url.database,'-Fc','-f',str(backup)],env={**os.environ,'PGPASSWORD':url.password or ''},
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120,creationflags=flags)
    if result.returncode: raise RuntimeError('backup failed; knowledge not changed')
    checked=subprocess.run([str(pg/'pg_restore.exe'),'--list',str(backup)],stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,timeout=30,creationflags=flags)
    if checked.returncode or not backup.stat().st_size: raise RuntimeError('backup unreadable; knowledge not changed')
    subprocess.run([sys.executable,str(root/'scripts/ingest_corpus.py'),str(ROOT/'corpus.json'),'--size','2000','--overlap','100'],
                   cwd=root,check=True)
    with Session(engine) as session,session.begin():
        added,updated=SkillIndexer(session).sync(SkillLoader(ROOT/'skills'))
    with engine.connect() as conn:
        after={str(i):hashlib.sha256(content.encode()).hexdigest() for i,content in conn.execute(text('select id,content from knowledge_chunks'))}
        if not all(after.get(i)==value for i,value in original.items()): raise ValueError('existing knowledge changed')
        if conn.execute(text('select version_num from alembic_version')).scalar_one()!=head: raise ValueError('unexpected migration change')
    record=dict(backup=str(backup),backup_bytes=backup.stat().st_size,migration=head,
                previous_chunks=len(original),current_chunks=len(after),previous_content_preserved=True,
                skills_added=added,skills_reindexed=updated,embedding_backfill='pending_separate_command')
    (root/'evaluation/hexstrike_knowledge_import_20261110.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record,ensure_ascii=True))
    engine.dispose()


if __name__=='__main__': main()
