# database.py
from sqlalchemy.types import TypeDecorator, CHAR, Text
from sqlalchemy.dialects.postgresql import UUID
from contextlib import contextmanager
from functools import wraps
from flask import request, redirect, session, abort

from Crypto.Util.number import long_to_bytes
from Crypto.Random.random import getrandbits
from Crypto.Protocol.KDF import PBKDF2

import uuid

from .app import db

@contextmanager
def transaction_on(db):
    try:
        yield
        db.session.commit()
    finally:
        db.session.rollback()

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

class User(db.Model):
	__tablename__ = 'user'
	id = db.Column(GUID, primary_key=True, default=uuid.uuid4)
	name = db.Column(db.Text, nullable=False)
	email = db.Column(db.Text, nullable=False, unique=True)
	salt = db.Column(db.LargeBinary)
	hash = db.Column(db.LargeBinary)
	cms_access = db.Column(db.Boolean, nullable=False, default=False)

	@db.validates('email')
	def validate_email(self, key, email_addr):
		if '@' not in email_addr:
			raise ValidationError('email')
		return email_addr

	def login(self, password):
		if self.hash is None and self.salt is None:
			# Set new password
			self.salt = long_to_bytes(getrandbits(128))
			self.hash = PBKDF2(password, self.salt)
		else:
			#actually check
			if self.hash != PBKDF2(password, self.salt):
				raise LoginError('password')
		session['user_id'] = self.id

class TempRedirect(db.Model):
	__tablename__ = 'redirect'
	id = db.Column(GUID, primary_key=True, default=uuid.uuid4)
	target = db.Column(db.Text, nullable=False)
	expires = db.Column(db.DateTime)
	data = db.Column(db.PickleType)

	def get_link(self):
		return '/tr/%s' % self.id

class RestrictedPage(db.Model):
	__tablename__ = 'restricted'
	path = db.Column(db.Text, primary_key=True)
	cms_access_required = db.Column(db.Boolean, default=False, nullable=False)
