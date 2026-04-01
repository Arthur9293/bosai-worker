from fastapi import APIRouter, Request

router = APIRouter()

@router.post("/send-lead-email")
async def send_lead_email(req: Request):
    data = await req.json()

    print("EMAIL_SIMULATION_RECEIVED:", data, flush=True)

    return {
        "ok": True,
        "message": "email_sent_simulation",
        "received": data,
    }
