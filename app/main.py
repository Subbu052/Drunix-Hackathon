from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:  # run as a package: uvicorn app.main:app
    from .chaincode import drunix_chain
except ImportError:  # run as a script from inside app/
    from chaincode import drunix_chain

app = FastAPI(title="PurposePay - Programmable Cross-Border CBDC Remittance")

# static/ lives next to the app/ package (project root), falling back to ./static
_candidates = [Path(__file__).resolve().parent.parent / "static", Path("static")]
STATIC_DIR = next((p for p in _candidates if (p / "index.html").exists()), _candidates[0])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class TransferRequest(BaseModel):
    currency: str = "USD"
    amount: float
    edu_pct: float = 40.0
    health_pct: float = 40.0
    gen_pct: float = 20.0


class PayRequest(BaseModel):
    merchant_id: str
    category: str
    amount_inr: float


def _error(message: str, status: int = 400, **extra) -> JSONResponse:
    # "detail" keeps the shape FastAPI's HTTPException uses, so older clients still work.
    return JSONResponse(status_code=status, content={"detail": message, **extra})


@app.get("/")
def read_root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PurposePay", "mode": "simulation"}


@app.get("/api/state")
def get_state():
    return drunix_chain.get_state()


@app.get("/api/compare")
def compare_swift(currency: str = "USD", amount: float = 1000.0,
                  edu_pct: float = 40.0, health_pct: float = 40.0, gen_pct: float = 20.0):
    try:
        return drunix_chain.simulate_traditional_swift(currency, amount, edu_pct, health_pct, gen_pct)
    except ValueError as exc:
        return _error(str(exc))


@app.post("/api/transfer")
def transfer_funds(req: TransferRequest):
    success, msg, result = drunix_chain.transfer(
        req.currency, req.amount, req.edu_pct, req.health_pct, req.gen_pct
    )
    if not success:
        return _error(msg, **result)
    return {"status": "SUCCESS", "message": msg, **result}


@app.post("/api/pay")
def pay_merchant(req: PayRequest):
    success, msg, details = drunix_chain.pay_merchant(req.merchant_id, req.category, req.amount_inr)
    if not success:
        return _error(msg, details=details)
    return {"status": "SUCCESS", "message": msg, "details": details}


@app.post("/api/reset")
def reset_demo():
    """Return the simulation to a clean state between demo runs."""
    return {"status": "RESET", "state": drunix_chain.reset()}
