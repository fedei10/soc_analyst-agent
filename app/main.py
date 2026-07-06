from fastapi import FastAPI

from app.services.groq.connection import test_groq_connection
from app.services.oxy.connection import oxy_connection
from app.config import settings 
app = FastAPI()

@app.get("/test")
def test_connections():
    return {

        "groq": test_groq_connection(),
        "oxy": oxy_connection()
        
    }
