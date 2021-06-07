from app.utilities.oauth2 import config_oauth
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import HTTPException
import json
from app.routers import poly, users, authentication, assets
from app.database.database_connector import database

app = FastAPI(title="Icosa API", redoc_url=None)

with open("config.json") as config_file:
    data = json.load(config_file)

SECRET_KEY = data["secret_key"]

app.config = {
    'OAUTH2_JWT_ISS': 'https://icosa.gallery',
    'OAUTH2_JWT_KEY': SECRET_KEY,
    'OAUTH2_JWT_ALG': 'HS256',
    'OAUTH2_TOKEN_EXPIRES_IN': {
        'authorization_code': 300
    },
    'OAUTH2_ERROR_URIS': [
        ('invalid_client', 'https://api.icosa.gallery/errors#invalid-client'),
    ]
}

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    '''Override the StarletteHTTPException exception'''
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )

#region database connection
@app.on_event("startup")
async def startup():
    await database.connect()
    print("Connected to database.")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    print("Disconnected from database.")
#endregion

@app.get("/", include_in_schema=False)
async def root():
    return "Icosa API"

app.include_router(authentication.router)
app.include_router(users.router)
app.include_router(assets.router)
app.include_router(poly.router)

app.mount("/authorization", StaticFiles(directory="static"), name="authentication")

origins = ["*"]

app.add_middleware(CORSMiddleware,
    allow_origins=origins,
    allow_headers=["*"],
    allow_methods=["*"]
)

config_oauth(app)
