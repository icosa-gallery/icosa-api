from typing import Text
import sqlalchemy
import sqlalchemy.dialects.postgresql
from sqlalchemy.sql.expression import null
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.sqltypes import BigInteger, Binary, String, Text
from app.utilities.snowflake import generate_snowflake

metadata = sqlalchemy.MetaData()

from app.database.database_connector import Base

import time
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin
)
from sqlalchemy.sql.sqltypes import BigInteger
from app.database.database_connector import Base


users = sqlalchemy.Table("users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.BigInteger, primary_key=True),
    sqlalchemy.Column("url", sqlalchemy.VARCHAR(255), nullable=False),
    sqlalchemy.Column("email", sqlalchemy.VARCHAR(255), nullable=False),
    sqlalchemy.Column("password", sqlalchemy.Binary),
    sqlalchemy.Column("displayname", sqlalchemy.VARCHAR(50), nullable=False),
    sqlalchemy.Column("description", sqlalchemy.TEXT),
)

assets = sqlalchemy.Table("assets",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.BigInteger, primary_key=True),
    sqlalchemy.Column("url", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("name", sqlalchemy.VARCHAR(255), nullable=False),
    sqlalchemy.Column("owner", sqlalchemy.BigInteger, sqlalchemy.ForeignKey("users.id"), nullable=False),
    sqlalchemy.Column("description", sqlalchemy.TEXT),
    sqlalchemy.Column("formats", sqlalchemy.dialects.postgresql.JSONB, nullable=False),
    sqlalchemy.Column("visibility", sqlalchemy.VARCHAR(255), nullable=False),
    sqlalchemy.Column("curated", sqlalchemy.BOOLEAN),
    sqlalchemy.Column("polyid", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("polydata", sqlalchemy.dialects.postgresql.JSONB),
    sqlalchemy.Column("thumbnail", sqlalchemy.TEXT),
)

expandedassets = sqlalchemy.Table("expandedassets",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.BigInteger),
    sqlalchemy.Column("url", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("name", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("owner", sqlalchemy.BigInteger),
    sqlalchemy.Column("ownername", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("ownerurl", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("formats", sqlalchemy.dialects.postgresql.JSONB),
    sqlalchemy.Column("description", sqlalchemy.TEXT),
    sqlalchemy.Column("visibility", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("curated", sqlalchemy.BOOLEAN),
    sqlalchemy.Column("polyid", sqlalchemy.VARCHAR(255)),
    sqlalchemy.Column("polydata", sqlalchemy.dialects.postgresql.JSONB),
    sqlalchemy.Column("thumbnail", sqlalchemy.TEXT),
)

class Users(Base):
    __tablename__ = "users"
    id = Column(BigInteger, primary_key=True)
    url = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    password = Column(Binary)
    displayname = Column(String(50), nullable=False)
    description = Column(Text)

    def get_user_id(self):
        '''Fetch user identifier'''
        return self.id

class OAuth2Client(Base, OAuth2ClientMixin):
    '''OAuth2Client class example'''

    __tablename__ = 'oauth2_client'

    id = Column(BigInteger, primary_key=True)


class OAuth2AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):
    '''OAuth2AuthorizationCode class example'''

    __tablename__ = 'oauth2_code'

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey('users.id', ondelete='CASCADE'))
    users = relationship('Users')

    def is_expired(self):
        return self.auth_time + 300 < time.time()


class OAuth2Token(Base, OAuth2TokenMixin):
    '''OAuth2Token class example'''

    __tablename__ = 'oauth2_token'

    id = Column(BigInteger, primary_key=True, default=generate_snowflake())
    user_id = Column(BigInteger, ForeignKey('users.id', ondelete='CASCADE'))
    users = relationship('Users')

    def is_refresh_token_active(self):
        '''Check if refresh token is active'''
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()