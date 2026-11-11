"""Verify legacy embeddings and backfill with optimistic, short database locks."""
import argparse
import json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true', help='explicitly write embeddings and provenance')
    parser.add_argument('--device', default='cpu')
    parser.add_argument('--batch-size', type=int, default=8)
    args = parser.parse_args()
    if not args.apply: raise SystemExit('explicit --apply is required')
    from huggingface_hub import snapshot_download
    from sentence_transformers import SentenceTransformer
    from sqlalchemy import create_engine
    from vulnmind.knowledge.model_fingerprint import MODEL, fingerprint, model_identity
    from vulnmind.config import Settings
    from vulnmind.knowledge.embedding_batch import optimistic_backfill
    from vulnmind.knowledge.vector import EMBEDDING_DIMENSIONS
    initial = fingerprint()
    info = model_identity(initial)
    def verify_model():
        if fingerprint() != initial:
            raise ValueError('model snapshot changed during backfill')
    path = snapshot_download(MODEL, revision=info['revision'], local_files_only=True)
    model = SentenceTransformer(path, device=args.device, trust_remote_code=False, local_files_only=True)
    if model.get_sentence_embedding_dimension() != EMBEDDING_DIMENSIONS:
        raise ValueError('model embedding dimensions do not match schema')
    engine = create_engine(Settings().database_url)
    try:
        result = optimistic_backfill(engine, model, model_info=info, verify_model=verify_model, batch_size=args.batch_size)
    finally:
        engine.dispose()
    print(json.dumps({'model': info, **result, 'note': 'local fingerprints are not signature authentication'},ensure_ascii=False))

if __name__ == '__main__': main()
