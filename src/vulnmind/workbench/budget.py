"""Local atomic reservations. Uncertain executions retain their full reservation."""
import sqlite3
from pathlib import Path


class BudgetExceeded(ValueError): pass


class BudgetExhausted(BudgetExceeded):
    """The global cap would be exceeded; callers may stop cleanly instead of failing."""


def affordable(ledger,amount):
    """True when a full worst-case reservation still fits (serial worker, no race)."""
    return ledger.snapshot()['available']>=amount


class BudgetLedger:
    def __init__(self,path,limit,*,must_exist=False):
        self.path=Path(path);self.limit=limit
        if must_exist and not self.path.is_file(): raise ValueError('budget ledger missing; cannot resume safely')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS config (singleton INTEGER PRIMARY KEY CHECK(singleton=1), cap INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, amount INTEGER NOT NULL, used INTEGER, CHECK(amount>=0), CHECK(used IS NULL OR (used>=0 AND used<=amount)))')
            db.execute('INSERT OR IGNORE INTO config VALUES (1,?)',(limit,))
            if db.execute('SELECT cap FROM config').fetchone()[0]!=limit: raise ValueError('budget binding changed')

    def connect(self): return sqlite3.connect(self.path,timeout=30)

    def reserve(self,identifier,amount):
        if not isinstance(amount,int) or isinstance(amount,bool) or amount<0: raise ValueError('invalid budget amount')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT amount FROM reservations WHERE id=?',(identifier,)).fetchone()
            if row:
                if row[0]!=amount: raise ValueError('reservation binding changed')
                return
            charged=db.execute('SELECT COALESCE(SUM(COALESCE(used,amount)),0) FROM reservations').fetchone()[0]
            if charged+amount>self.limit: raise BudgetExhausted('global request budget exhausted')
            db.execute('INSERT INTO reservations VALUES (?,?,NULL)',(identifier,amount))

    def try_reserve(self,identifier,amount):
        """Reserve if it fits; return False on exhaustion, raise on binding errors."""
        try:
            self.reserve(identifier,amount)
            return True
        except BudgetExhausted:
            return False

    def settle(self,identifier,used):
        if not isinstance(used,int) or isinstance(used,bool) or used<0: raise ValueError('invalid usage')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT amount,used FROM reservations WHERE id=?',(identifier,)).fetchone()
            if not row or used>row[0]: raise ValueError('receipt exceeded reservation')
            if row[1] is not None and row[1]!=used: raise ValueError('usage receipt changed')
            db.execute('UPDATE reservations SET used=? WHERE id=?',(used,identifier))

    def snapshot(self):
        with self.connect() as db:
            rows=db.execute('SELECT id,amount,used FROM reservations ORDER BY id').fetchall()
        charged=sum(used if used is not None else amount for _,amount,used in rows)
        return dict(limit=self.limit,charged=charged,available=self.limit-charged,
                    uncertain_reservations=sum(used is None for _,_,used in rows),
                    stop_reason='budget_exhausted' if charged>=self.limit else None,
                    reservations=[dict(id=k,amount=n,used=u) for k,n,u in rows])
