import sys
from os.path import dirname
sys.path.append(dirname(__file__) + "/../../src")

from fastapi import FastAPI, Request
from dotenv import load_dotenv
import datetime
from typing import Dict, Any

from crossauth_backend import CrossauthLogger
from crossauth_fastapi import FastApiServer, FastApiSessionServer

CrossauthLogger.logger().level = CrossauthLogger.Debug

load_dotenv()


app = FastAPI()

# create the server, pointing it at the app we created
server = FastApiServer({ 
    "oauth_resserver": {
        "options": {
            "protected_endpoints": {"/resource": {"scope": ["read"], "accept_session_authorization": False}}
        } 
    }}, { 
    "app": app,
    "site_url": "http://localhost:8001",
})

@app.get("/resource")
async def resource(request : Request) -> Dict[str,Any]:
    return {
        "username": FastApiSessionServer.username(request),
        "timestamp": datetime.datetime.now()
    }