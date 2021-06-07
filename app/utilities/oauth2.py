'''OIDC server example'''

from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7662 import IntrospectionEndpoint as _IntrospectionEndpoint
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core import UserInfo
from werkzeug.security import gen_salt
import bcrypt
from authlib.integrations.fastapi_oauth2 import AuthorizationServer, ResourceProtector
from app.database.database_schema import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
from app.database.database_connector import database, db
from app.database.database_schema import users, Users
from app.utilities.snowflake import generate_snowflake
import json
from fastapi import FastAPI

with open("config.json") as config_file:
    data = json.load(config_file)

SECRET_KEY = data["secret_key"]

JWT_CONFIG = {
    'key': SECRET_KEY,
    'alg': 'HS256',
    'iss': 'https://icosa.gallery',
    'exp': 3600,
}

def exists_nonce(nonce, req):
    '''Check nonce existance'''
    exists = db.query(OAuth2AuthorizationCode).filter(  # pylint: disable=E1101
        OAuth2Client.client_id == req.client_id, OAuth2AuthorizationCode.nonce == nonce).first()
    return bool(exists)


def generate_user_info(user, scope):
    '''Generates the user profile information'''
    user_info = UserInfo(sub=str(user.id))
    user_info['id'] = user.id
    if 'email' in scope:
        user_info['email'] = user.email
    return user_info


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    '''AuthorizationCodeGrant class'''

    def generate_authorization_code(self):
        return gen_salt(48)

    def save_authorization_code(self, code, request):
        nonce = request.data.get('nonce')
        item = OAuth2AuthorizationCode(
            id=generate_snowflake(),
            code=code,
            client_id=self.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user["id"],
            nonce=nonce
        )
        db.add(item)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101

    def query_authorization_code(self, code, client):  # pylint: disable=R1710
        '''Query the authorization code'''
        item = db.query(OAuth2AuthorizationCode).filter(  # pylint: disable=E1101
            OAuth2AuthorizationCode.code == code,
            OAuth2Client.client_id == client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.delete(authorization_code)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101

    def authenticate_user(self, authorization_code):
        return db.query(Users).filter(  # pylint: disable=E1101
            Users.id == authorization_code.user_id).first()


class RefreshTokenGrant(grants.RefreshTokenGrant):
    '''RefreshTokenGrant class'''

    def authenticate_refresh_token(self, refresh_token):  # pylint: disable=R1710
        token = db.query(OAuth2Token).filter(  # pylint: disable=E1101
            OAuth2Token.refresh_token==refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return db.query(Users).filter(  # pylint: disable=E1101
            Users.id == credential.user_id).first()

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.add(credential)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101


class IntrospectionEndpoint(_IntrospectionEndpoint):
    '''IntrospectionEndpoint class'''

    def query_token(self, token, token_type_hint, client):  # pylint: disable=R1710
        if token_type_hint == 'access_token':
            tok = db.query(OAuth2Token).filter(  # pylint: disable=E1101
                OAuth2Token.access_token == token).first()
        elif token_type_hint == 'refresh_token':
            tok = db.query(OAuth2Token).filter(  # pylint: disable=E1101
                OAuth2Token.refresh_token == token).first()
        else:
            tok = db.query(OAuth2Token).filter(  # pylint: disable=E1101
                OAuth2Token.access_token == token).first()
            if not tok:
                tok = db.query(OAuth2Token).filter(  # pylint: disable=E1101
                    OAuth2Token.refresh_token == token).first()
        if tok:
            if tok.client_id == client.client_id:
                return tok

    def introspect_token(self, token):
        return {
            'active': True,
            'client_id': token.client_id,
            'token_type': token.token_type,
            'username': token.user_id,
            'scope': token.get_scope(),
            'sub': token.user.uuid,
            'aud': token.client_id,
            'iss': JWT_CONFIG.get('iss'),
            'exp': token.expires_in,
            'iat': token.issued_at,
        }


class OpenIDCode(_OpenIDCode):
    '''OpenIDCode class'''

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


authorization = AuthorizationServer()
require_oauth = ResourceProtector()


def config_oauth(app: FastAPI):
    '''Setup the application configuration'''
    query_client = create_query_client_func(db, OAuth2Client)
    save_token = create_save_token_func(db, OAuth2Token)
    authorization.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )

    authorization.register_grant(AuthorizationCodeGrant, [
        OpenIDCode(require_nonce=True),
    ])
    authorization.register_grant(RefreshTokenGrant)
    authorization.register_endpoint(IntrospectionEndpoint)

    revocation_cls = create_revocation_endpoint(db, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    bearer_cls = create_bearer_token_validator(db, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
