
from authlib.oauth2 import OAuth2Error
from datetime import timedelta
from fastapi import APIRouter, Request, Form, status, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm

from app.utilities.schema_models import LoginToken
import app.utilities.authentication as authentication

router = APIRouter(
    prefix="/oauth",
    tags=["Authentication"])

ACCESS_TOKEN_EXPIRE_MINUTES = 43800

# @router.post("", response_model=LoginToken)
# @router.post("/", response_model=LoginToken, include_in_schema=False)
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = jsonable_encoder(await authentication.authenticate_user(form_data.username, form_data.password))
#     if not user:
#         raise HTTPException(status_code=401, detail="Incorrect username or password.", headers={"WWW-Authenticate": "Bearer"})
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = authentication.create_access_token(data={"sub": user["email"]}, expires_delta=access_token_expires)
#     return {"access_token": access_token, "token_type": "bearer"}

@router.post('/oauth/authorize')
def authorize(
        request: Request,
        uuid: str = Form(...)):
    '''Provide authorization code response'''
    user = db.query(User).filter(User.uuid == uuid).first()  # pylint: disable=E1101

    if not user:
        user = User(uuid=uuid)
        db.add(user)  # pylint: disable=E1101
        db.commit()  # pylint: disable=E1101

    request.body = {
        'uuid': uuid
    }

    try:
        authorization.validate_consent_request(request=request, end_user=user)
    except OAuth2Error as error:
        return dict(error.get_body())

    return authorization.create_authorization_response(request=request, grant_user=user)


@router.post('/oauth/token')
def token(
        request: Request,
        grant_type: str = Form(...),
        scope: str = Form(None),
        code: str = Form(None),
        refresh_token: str = Form(None),
        code_verifier: str = Form(None),
        client_id: str = Form(None),
        client_secret: str = Form(None)):
    '''Exchange the authorization code to access token'''
    request.body = {
        'grant_type': grant_type,
        'scope': scope,
    }
    if grant_type == 'authorization_code':
        request.body['code'] = code
    elif grant_type == 'refresh_token':
        request.body['refresh_token'] = refresh_token

    if code_verifier:
        request.body['code_verifier'] = code_verifier

    if client_id:
        request.body['client_id'] = client_id

    if client_secret:
        request.body['client_secret'] = client_secret

    return authorization.create_token_response(request=request)


@router.post('/oauth/introspect')
def introspect_token(
        request: Request,
        token: str = Form(...),  # pylint: disable=W0621
        token_type_hint: str = Form(...)):
    '''Introspect the token using access token'''
    request.body = {}

    if token:
        request.body.update({'token': token})

    if token_type_hint:
        request.body.update({'token_type_hint': token_type_hint})

    return authorization.create_endpoint_response('introspection', request=request)


@router.post('/oauth/revoke')
def revoke_token(
        request: Request,
        token: str = Form(...),  # pylint: disable=W0621
        token_type_hint: str = Form(...)):
    '''Revoke the token using access token'''
    request.body = {}

    if token:
        request.body.update({'token': token})

    if token_type_hint:
        request.body.update({'token_type_hint': token_type_hint})

    return authorization.create_endpoint_response('revocation', request=request)


@router.get('/oauth/userinfo')
def userinfo(request: Request):
    '''Request user profile information'''
    with require_oauth.acquire(request, 'profile') as token:  # pylint: disable=W0621
        return generate_user_info(token.user, token.scope)