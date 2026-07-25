from fastapi import FastAPI

from app.routers import health
from app.routers import capture
from app.database import database

app = FastAPI(title="FlowTrace")

app.include_router(health.router)
app.include_router(capture.router)


@app.get("/")
def root():
    return {
        "message": "Welcome to FlowTrace"
    }