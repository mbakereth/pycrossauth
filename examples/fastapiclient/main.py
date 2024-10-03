import sys
from os.path import dirname
sys.path.append(dirname(__file__) + "/../../src")

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles # type: ignore
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine
import os
from fastapi.templating import Jinja2Templates

from crossauth_backend import CrossauthLogger
from crossauth_backend import SqlAlchemyKeyStorage
from crossauth_fastapi import FastApiServer, BffEndpoint

CrossauthLogger.logger().level = CrossauthLogger.Debug

load_dotenv()

engine = create_async_engine(
    os.environ["DATABASE_URL"],
    echo=True
)

key_storage = SqlAlchemyKeyStorage(engine)
app = FastAPI()
templates = Jinja2Templates("templates")
app.mount("/public", StaticFiles(directory="public"), name="static") # type: ignore

# create the server, pointing it at the app we created
server = FastApiServer({ 
    "session": { 
        "key_storage": key_storage,
    }, \
    "oauth_client": {
        "auth_server_base_url": os.environ["AUTH_SERVER_BASE_URL"],
        "options": {
            "delete_tokens_get_url": "deletetokens",
            "delete_tokens_post_url": "deletetokens",
        } 
    }}, { 
    "app": app,
    "template_dir": "templates",
    "site_url": "http://localhost:8000",
    "valid_flows": ["all"], 
    "token_response_type": "save_in_session_and_redirect",
    "error_response_type": "page_error",
    "bff_endpoints": [BffEndpoint("/resource", ["GET"], False)],
    "bff_base_url": os.environ["RESOURCE_SERVER"],
    "token_endpoints": ["id_token", "access_token", "refresh_token", "have_access_token", "have_id_token", "have_refresh_token"], 
})

@app.get("/")
async def root(request : Request):
    return templates.TemplateResponse(
        request=request,
        name="index.jinja2",
        context={"csrf_token": request.state.csrf_token}
    )

@app.get("/authzcodeex")
async def authzcodeex(request : Request):
    return templates.TemplateResponse(
        request=request,
        name="authzcodeex.jinja2",
        context={"csrf_token": request.state.csrf_token}
    )

@app.get("/authorized")
async def authorized(request : Request):
    return templates.TemplateResponse(
        request=request,
        name="authorized.jinja2",
        context={"csrf_token": request.state.csrf_token}
    )
