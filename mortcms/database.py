# database.py
from sqlalchemy.types import TypeDecorator, CHAR, Text
from sqlalchemy.dialects.postgresql import UUID
from contextlib import contextmanager
from functools import wraps
from flask import request, redirect, session, abort, current_app
import uuid

class GUID(TypeDecorator):
    """Platform-independent GUID type.

    Ripped directly from SQLAlchemy Documentation
    http://docs.sqlalchemy.org/en/rel_0_9/core/types.html#backend-agnostic-guid-type

    See SQLAlchemy Liscence TODO

    Uses Postgresql's UUID type, otherwise uses
    CHAR(32), storing as stringified hex values.

    """
    impl = CHAR

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value)
            else:
                # hexstring
                return "%.32x" % value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            return uuid.UUID(value)

@contextmanager
def transaction_on(db):
    try:
        yield
        db.session.commit()
    finally:
        db.session.rollback()