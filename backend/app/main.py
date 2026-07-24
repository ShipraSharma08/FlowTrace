

from fastapi import FastAPI
from backend.app.routers import health, interfaces, capture

app = FastAPI(
    title="FlowTrace API",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "project": "FlowTrace",
        "status": "Running"
    }


app.include_router(health.router)
app.include_router(interfaces.router)
app.include_router(capture.router)