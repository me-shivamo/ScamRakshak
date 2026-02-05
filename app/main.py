"""
ScamRakshak - Agentic Honey-Pot API

This is the main entry point of our application.
It creates the FastAPI app and defines all the endpoints.

ENDPOINTS:
- POST /     : Main honeypot endpoint (receives scam messages)
- GET /health: Health check for Railway/Render

FLOW:
1. GUVI sends a message to POST /
2. We validate the API key
3. We detect if it's a scam
4. We generate a response using our AI agent
5. We extract intelligence from the message
6. We return the response
7. When conversation ends, we send callback to GUVI
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.models.schemas import HoneypotRequest, HoneypotResponse
from app.core.scam_detector import scam_detector
from app.core.agent import honeypot_agent
from app.core.intelligence import intelligence_extractor
from app.services.session_manager import session_manager
from app.services.callback_service import callback_service

# ===== Configure Logging =====
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ===== Background Tasks =====

async def cleanup_task():
    """
    Background task to clean up expired sessions.
    Runs every 5 minutes.
    """
    while True:
        try:
            await asyncio.sleep(300)  # Wait 5 minutes
            cleaned = await session_manager.cleanup_expired()
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} expired sessions")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")


async def conversation_monitor_task():
    """
    Background task to detect ended conversations and send callbacks.
    Runs every minute.
    """
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            # Find inactive sessions
            inactive_sessions = await session_manager.get_inactive_sessions()

            for session in inactive_sessions:
                if not session.callback_sent and session.scam_detected:
                    logger.info(
                        f"Conversation ended (inactive) for session {session.session_id}. "
                        f"Sending callback..."
                    )

                    # Mark as ended
                    await session_manager.mark_conversation_ended(session.session_id)

                    # Send callback to GUVI
                    success = await callback_service.send_callback(session)

                    if success:
                        await session_manager.mark_callback_sent(session.session_id)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Conversation monitor error: {e}")


# ===== Application Lifecycle =====

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    This runs code when the app starts and stops.
    We use it to start/stop background tasks.
    """
    logger.info("ScamRakshak API starting...")

    # Start background tasks
    cleanup = asyncio.create_task(cleanup_task())
    monitor = asyncio.create_task(conversation_monitor_task())

    logger.info("Background tasks started")

    yield  # App is running

    # Shutdown: Cancel background tasks
    cleanup.cancel()
    monitor.cancel()

    logger.info("ScamRakshak API stopped")


# ===== Create FastAPI App =====

app = FastAPI(
    title="ScamRakshak",
    description="Agentic Honey-Pot API for Scam Detection & Intelligence Extraction",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware (allows requests from any origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===== API Key Verification =====

async def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")) -> str:
    """
    Verify the API key from request header.

    If the key is invalid, return 401 Unauthorized.
    """
    if x_api_key != settings.API_KEY:
        logger.warning(f"Invalid API key attempt")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return x_api_key


# ===== Exception Handler =====

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Handle any unhandled exceptions.

    Returns a valid response even if something goes wrong internally.
    """
    logger.error(f"Unhandled exception: {exc}")

    # Return a response that keeps the scammer engaged
    # (They shouldn't know something went wrong)
    return JSONResponse(
        status_code=200,  # Still return 200 to not break the conversation
        content={
            "status": "success",
            "reply": "Haan ji beta, network thoda slow hai... aap dobara batao?"
        }
    )


# ===== Health Check Endpoint =====

@app.get("/health")
async def health_check():
    """
    Health check endpoint for Railway/Render.

    They ping this endpoint to check if the service is running.
    """
    stats = session_manager.get_stats()
    return {
        "status": "healthy",
        "service": "ScamRakshak",
        "version": "1.0.0",
        "sessions": stats
    }


# ===== Main Honeypot Endpoint =====

@app.post("/", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Main honeypot endpoint - receives scam messages and responds.

    This is the core of our application!

    Flow:
    1. Validate API key
    2. Get/create session
    3. Extract intelligence from message
    4. Detect if it's a scam
    5. Generate honeypot response
    6. Update session
    7. Check if conversation should end
    8. Return response
    """
    # Step 1: Verify API key
    await verify_api_key(x_api_key)

    logger.info(f"Received message for session {request.sessionId}")

    try:
        # Step 2: Get or create session
        channel = request.metadata.channel if request.metadata else None
        language = request.metadata.language if request.metadata else "English"

        session = await session_manager.get_or_create(
            session_id=request.sessionId,
            channel=channel,
            language=language
        )

        # Step 3: Extract intelligence from the scammer's message
        session.extracted_intelligence = await intelligence_extractor.extract(
            text=request.message.text,
            existing=session.extracted_intelligence
        )

        # Step 4: Detect if this is a scam
        is_scam, confidence, scam_type, indicators = await scam_detector.detect(
            message=request.message.text,
            conversation_history=session.conversation_history,
            existing_confidence=session.scam_confidence
        )

        # Update session with detection results
        session.scam_detected = is_scam
        session.scam_confidence = confidence
        session.scam_type = scam_type

        # Step 5: Generate honeypot response
        response_text, agent_note = await honeypot_agent.generate_response(
            scammer_message=request.message.text,
            conversation_history=session.conversation_history,
            scam_type=scam_type,
            extracted_intel=session.extracted_intelligence.model_dump()
        )

        # Step 6: Update conversation history
        # Add scammer's message
        session.conversation_history.append({
            "role": "scammer",
            "content": request.message.text
        })
        # Add our response
        session.conversation_history.append({
            "role": "agent",
            "content": response_text
        })

        # Update message count
        session.total_messages += 2

        # Add agent note
        session.agent_notes.append(agent_note)

        # Step 7: Check if conversation should end
        if should_end_conversation(request.message.text, session):
            session.conversation_ended = True
            # Send callback in background
            background_tasks.add_task(
                send_callback_background,
                session.session_id
            )

        # Step 8: Save session
        await session_manager.update(request.sessionId, session)

        logger.info(
            f"Session {request.sessionId}: "
            f"scam={is_scam}, confidence={confidence:.2f}, "
            f"messages={session.total_messages}"
        )

        # Return response
        return HoneypotResponse(
            status="success",
            reply=response_text
        )

    except Exception as e:
        logger.error(f"Error processing message: {e}")
        # Return a generic response to keep the conversation going
        return HoneypotResponse(
            status="success",
            reply="Achha achha... thoda samajh nahi aaya, phir se batao beta?"
        )


# ===== Helper Functions =====

def should_end_conversation(message: str, session) -> bool:
    """
    Detect if the conversation should end.

    Triggers:
    - Explicit end signals from scammer
    - Conversation too long (>50 messages)
    - Scammer realized it's a trap
    """
    message_lower = message.lower()

    # End signals
    end_signals = [
        "bye", "goodbye", "stop", "block", "report",
        "police", "fraud", "scam", "fake", "cheat",
        "don't contact", "stop messaging", "harassment"
    ]

    for signal in end_signals:
        if signal in message_lower:
            return True

    # Too many messages (conversation is likely complete)
    if session.total_messages > 50:
        return True

    return False


async def send_callback_background(session_id: str):
    """
    Send callback in the background.

    This is called when we detect the conversation has ended.
    """
    session = await session_manager.get(session_id)
    if session and not session.callback_sent:
        logger.info(f"Sending callback for session {session_id}")
        success = await callback_service.send_callback(session)
        if success:
            await session_manager.mark_callback_sent(session_id)


# ===== Run the App =====

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
