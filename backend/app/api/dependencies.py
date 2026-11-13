from __future__ import annotations

from fastapi import Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.tables import Analysis


def get_analysis_or_404(analysis_id: str, db: Session = Depends(get_db)) -> Analysis:
    a = db.get(Analysis, analysis_id)
    if a is None:
        raise HTTPException(404, f"Analysis '{analysis_id}' not found")
    return a


def page_params(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)) -> tuple[int, int]:
    return page, page_size


def paginate(query, page: int, page_size: int, convert):
    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [convert(r) for r in rows], "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}
