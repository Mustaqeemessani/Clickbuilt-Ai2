from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pathlib import Path
import os
import stripe
import logging
from tinydb import TinyDB, Query

app = FastAPI()

# ---------------- LOGGER SETUP ----------------
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "webhook.log"
DB_FILE = BASE_DIR / "db.json"

logger = logging.getLogger("stripe-webhook")
logger.setLevel(logging.INFO)

# File handler writes to BASE_DIR/webhook.log
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
file_handler.setFormatter(formatter)

# Add handler only once
if not logger.handlers:
    logger.addHandler(file_handler)

logger.propagate = False  # prevent uvicorn from duplicating logs
# ------------------------------------------------

db = TinyDB(DB_FILE)

# NEVER hardcode secrets — use env vars instead
stripe.api_key = os.getenv("API_KEY") # e.g. "sk_live_..."
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET") # e.g. "whsec_..."


def _extract_email_from_event_object(obj: dict) -> str | None:
    """Best-effort extraction of a customer's email from common event objects."""
    try:
        # Newer sessions keep it under customer_details.email; older had customer_email
        email = obj.get("customer_email") or (obj.get("customer_details") or {}).get("email")
        if not email and obj.get("customer"):
            # Fallback: retrieve the Customer to get email
            cust = stripe.Customer.retrieve(obj["customer"])  # type: ignore[arg-type]
            email = cust.get("email")
        return email
    except Exception:
        return None


def process_event_record(event_id: str, event_type: str) -> None:
    """Runs outside the request cycle. Fetches the event fresh from Stripe and handles it."""
    try:
        ev = stripe.Event.retrieve(event_id)
        obj = ev.get("data", {}).get("object", {})  # type: ignore[assignment]
    except Exception:
        logger.exception("Failed to retrieve event from Stripe (id=%s)", event_id)
        return

    logger.info("Processing event %s (%s)", event_id, event_type)

    try:
        if event_type == "checkout.session.completed":
            email = _extract_email_from_event_object(obj) or "unknown"
            logger.info("✅ Checkout completed by %s | session=%s", email, obj.get("id"))
            # TODO: grant access / fulfill order here

        elif event_type == "payment_intent.succeeded":
            amount = obj.get("amount_received") or obj.get("amount")
            currency = obj.get("currency")
            logger.info("💸 Payment succeeded: %s %s | intent=%s", amount, currency, obj.get("id"))
            # TODO: mark order paid

        else:
            logger.info("ℹ️ Unhandled event type: %s", event_type)

    except Exception:
        logger.exception("Handler crashed for event %s (%s)", event_id, event_type)


@app.get("/")
async def read_index():
    logger.info("GET /")
    index_path = BASE_DIR / "templates" / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return JSONResponse({"status": "ok", "message": "no index.html found"})


@app.post("/api/payment/callback")
async def payment_callback(request: Request, background_tasks: BackgroundTasks):
    logger.info("POST /api/payment/callback")

    if not WEBHOOK_SECRET:
        logger.error("Webhook secret not configured")
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    try:
        # --- Read payload & signature ---
        payload = await request.body()
        sig_header = request.headers.get("stripe-signature")

        if not sig_header:
            raise HTTPException(status_code=400, detail="Missing stripe-signature header")

        # --- Verify event with Stripe ---
        try:
            event = stripe.Webhook.construct_event(
                payload=payload,  # type: ignore[arg-type]
                sig_header=sig_header,
                secret=WEBHOOK_SECRET,
            )
        except TypeError:
            # stripe-python expects text in some versions – fall back to utf-8 string
            event = stripe.Webhook.construct_event(
                payload=payload.decode("utf-8"),
                sig_header=sig_header,
                secret=WEBHOOK_SECRET,
            )

        event_id = event.get("id")
        event_type = event.get("type")

        if not event_id or not event_type:
            raise HTTPException(status_code=400, detail="Malformed event (missing id/type)")

        # --- Prevent duplicates ---
        if db.contains(Query().event_id == event_id):
            logger.info("Duplicate event received: %s", event_id)
            return JSONResponse(status_code=200, content={"received": True, "duplicate": True})

        # --- Store event id & type only ---
        db.insert({"event_id": event_id, "type": event_type})

        # --- Run background task ---
        background_tasks.add_task(process_event_record, event_id, event_type)

        return JSONResponse(status_code=200, content={"received": True})

    except stripe.error.SignatureVerificationError:
        logger.warning("Invalid Stripe signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    except HTTPException:
        # Re-raise the HTTPException we created above
        raise

    except Exception as e:
        logger.exception("Unexpected error while handling webhook: %s", e)
        raise HTTPException(status_code=500, detail="Webhook processing error")


if __name__ == "__main__":
    # Run with: python main.py  (or: uvicorn main:app --host 0.0.0.0 --port 8000)
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
