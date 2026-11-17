import asyncio
from pathlib import Path

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, desc

from database import AsyncSessionLocal
from models import Simulation, TelemetryLog
from red_ai import run_reconnaissance
from sse_manager import sse_manager


app = FastAPI(
    title="Cyber Mirror API",
    description="Cyber Mirror Sprint 2 Backend",
    version="1.0.0"
)


# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database connection
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# Request schemas
class SimulationCreate(BaseModel):
    name: str


class TelemetryCreate(BaseModel):
    simulation_id: int
    event_type: str
    source: str
    payload: dict = Field(default_factory=dict)


# Blue AI configuration file shared with the Arena container
BLUE_AI_CONFIG_PATH = Path(
    "/app/arena/security-headers.conf"
)


# Only these predefined security-header mitigations are allowed.
APPROVED_MITIGATIONS = {
    "content-security-policy":
        "add_header Content-Security-Policy "
        "\"default-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'\" always;",

    "x-frame-options":
        'add_header X-Frame-Options "DENY" always;',

    "x-content-type-options":
        'add_header X-Content-Type-Options "nosniff" always;',

    "referrer-policy":
        'add_header Referrer-Policy '
        '"strict-origin-when-cross-origin" always;'
}


# Common telemetry broadcast helper
async def broadcast_telemetry(log):
    await sse_manager.broadcast({
        "id": log.id,
        "simulation_id": log.simulation_id,
        "event_type": log.event_type,
        "source": log.source,
        "payload": log.payload,
        "created_at": log.created_at.isoformat()
    })


# Save telemetry to PostgreSQL and broadcast it through SSE
async def save_telemetry(
    db,
    simulation_id,
    event_type,
    source,
    payload
):
    log = TelemetryLog(
        simulation_id=simulation_id,
        event_type=event_type,
        source=source,
        payload=payload
    )

    db.add(log)
    await db.commit()
    await db.refresh(log)

    await broadcast_telemetry(log)

    return log


# Home route
@app.get("/")
async def home():
    return {
        "message": "Cyber Mirror Backend is running!",
        "status": "success"
    }


# Health check
@app.get("/health")
async def health():
    return {"status": "healthy"}


# Database health check
@app.get("/db-health")
async def db_health(
    db: AsyncSession = Depends(get_db)
):
    await db.execute(text("SELECT 1"))
    return {"database": "connected"}


# Create simulation
@app.post("/simulations")
async def create_simulation(
    data: SimulationCreate,
    db: AsyncSession = Depends(get_db)
):
    simulation = Simulation(name=data.name)

    db.add(simulation)
    await db.commit()
    await db.refresh(simulation)

    return {
        "id": simulation.id,
        "name": simulation.name,
        "status": simulation.status
    }


# Get all simulations
@app.get("/simulations")
async def get_simulations(
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Simulation)
    )

    simulations = result.scalars().all()

    return [
        {
            "id": item.id,
            "name": item.name,
            "status": item.status
        }
        for item in simulations
    ]


# Create a telemetry log manually
@app.post("/telemetry")
async def create_telemetry(
    data: TelemetryCreate,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Simulation).where(
            Simulation.id == data.simulation_id
        )
    )

    simulation = result.scalar_one_or_none()

    if simulation is None:
        raise HTTPException(
            status_code=404,
            detail="Simulation not found"
        )

    log = await save_telemetry(
        db,
        data.simulation_id,
        data.event_type,
        data.source,
        data.payload
    )

    return {
        "id": log.id,
        "simulation_id": log.simulation_id,
        "event_type": log.event_type,
        "source": log.source,
        "payload": log.payload
    }


# Get telemetry logs for a simulation
@app.get("/simulations/{simulation_id}/telemetry")
async def get_telemetry(
    simulation_id: int,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Simulation).where(
            Simulation.id == simulation_id
        )
    )

    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=404,
            detail="Simulation not found"
        )

    result = await db.execute(
        select(TelemetryLog)
        .where(
            TelemetryLog.simulation_id == simulation_id
        )
        .order_by(TelemetryLog.id)
    )

    logs = result.scalars().all()

    return [
        {
            "id": log.id,
            "simulation_id": log.simulation_id,
            "event_type": log.event_type,
            "source": log.source,
            "payload": log.payload,
            "created_at": (
                log.created_at.isoformat()
                if log.created_at else None
            )
        }
        for log in logs
    ]


# Run Red AI reconnaissance
@app.post("/red-ai/run")
async def run_red_ai(
    simulation_id: int,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Simulation).where(
            Simulation.id == simulation_id
        )
    )

    simulation = result.scalar_one_or_none()

    if simulation is None:
        raise HTTPException(
            status_code=404,
            detail="Simulation not found"
        )

    scan_result = await run_reconnaissance()

    log = await save_telemetry(
        db,
        simulation_id,
        "reconnaissance",
        "Red AI",
        scan_result
    )

    return {
        "message": "Red AI reconnaissance executed",
        "simulation_id": simulation_id,
        "telemetry_id": log.id,
        "result": scan_result
    }


# Blue AI automated mitigation
@app.post("/blue-ai/mitigate")
async def run_blue_ai(
    simulation_id: int,
    db: AsyncSession = Depends(get_db)
):
    # Step 1: Verify that the simulation exists.
    result = await db.execute(
        select(Simulation).where(
            Simulation.id == simulation_id
        )
    )

    simulation = result.scalar_one_or_none()

    if simulation is None:
        raise HTTPException(
            status_code=404,
            detail="Simulation not found"
        )

    # Step 2: Retrieve the latest Red AI reconnaissance.
    result = await db.execute(
        select(TelemetryLog)
        .where(
            TelemetryLog.simulation_id == simulation_id,
            TelemetryLog.event_type == "reconnaissance",
            TelemetryLog.source == "Red AI"
        )
        .order_by(desc(TelemetryLog.id))
        .limit(1)
    )

    red_log = result.scalar_one_or_none()

    if red_log is None:
        raise HTTPException(
            status_code=400,
            detail="Run Red AI reconnaissance before Blue AI mitigation"
        )

    # Step 3: Read Red AI findings.
    missing_headers = (
        red_log.payload.get("missing_security_headers", []) or []
    )

    if not isinstance(missing_headers, list):
        raise HTTPException(
            status_code=400,
            detail="Invalid Red AI findings format"
        )

    # Step 4: Select only approved mitigations.
    selected_mitigations = [
        header
        for header in missing_headers
        if header in APPROVED_MITIGATIONS
    ]

    if not selected_mitigations:
        return {
            "message": "No approved mitigations required",
            "simulation_id": simulation_id,
            "status": "no_action_required"
        }

    # Step 5: Generate the controlled Nginx configuration.
    config_lines = [
        APPROVED_MITIGATIONS[header]
        for header in selected_mitigations
    ]

    configuration = (
        "# Cyber Mirror Blue AI Security Configuration\n"
        + "\n".join(config_lines)
        + "\n"
    )

    # Step 6: Write the configuration to the shared file.
    try:
        BLUE_AI_CONFIG_PATH.write_text(
            configuration,
            encoding="utf-8"
        )
    except OSError as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to write mitigation configuration: {error}"
        )

    # Step 7: Allow the Arena Nginx watcher to detect and reload.
    await asyncio.sleep(5)

    # Step 8: Verify the mitigation by running Red AI again.
    verification = await run_reconnaissance()

    successfully_applied = []

    if verification.get("status") != "completed":
        mitigation_status = "verification_failed"
    else:
        remaining_missing = (
            verification.get("missing_security_headers", []) or []
        )

        successfully_applied = [
            header
            for header in selected_mitigations
            if header not in remaining_missing
        ]

        mitigation_status = (
            "completed"
            if len(successfully_applied) == len(selected_mitigations)
            else "partially_completed"
        )

    # Step 9: Save Blue AI telemetry.
    blue_result = {
        "status": mitigation_status,
        "target": "arena-web",
        "action": "Automated security header mitigation",
        "applied_mitigations": selected_mitigations,
        "successfully_applied": successfully_applied,
        "verification": verification
    }

    log = await save_telemetry(
        db,
        simulation_id,
        "mitigation",
        "Blue AI",
        blue_result
    )

    # Step 10: Return the result.
    return {
        "message": "Blue AI mitigation executed",
        "simulation_id": simulation_id,
        "telemetry_id": log.id,
        "result": blue_result
    }


# Purple AI scoring engine
@app.post("/purple-ai/score")
async def run_purple_ai(
    simulation_id: int,
    db: AsyncSession = Depends(get_db)
):
    # Step 1: Verify that the simulation exists.
    result = await db.execute(
        select(Simulation).where(
            Simulation.id == simulation_id
        )
    )

    simulation = result.scalar_one_or_none()

    if simulation is None:
        raise HTTPException(
            status_code=404,
            detail="Simulation not found"
        )

    # Step 2: Get the latest Red AI reconnaissance record.
    result = await db.execute(
        select(TelemetryLog)
        .where(
            TelemetryLog.simulation_id == simulation_id,
            TelemetryLog.event_type == "reconnaissance",
            TelemetryLog.source == "Red AI"
        )
        .order_by(desc(TelemetryLog.id))
        .limit(1)
    )

    red_log = result.scalar_one_or_none()

    if red_log is None:
        raise HTTPException(
            status_code=400,
            detail="Run Red AI reconnaissance before Purple AI scoring"
        )

    red_data = red_log.payload or {}

    # Step 3: Calculate coverage of the available security-header checks.
    security_headers = red_data.get("security_headers")

    if not isinstance(security_headers, list):
        raise HTTPException(
            status_code=400,
            detail="Red AI telemetry does not contain a valid security_headers list"
        )

    applicable_checks = [
        item
        for item in security_headers
        if isinstance(item, dict)
        and item.get("status") != "not_applicable"
    ]

    detected_checks = [
        item
        for item in applicable_checks
        if item.get("status") in ("present", "missing")
    ]

    total_checks = len(applicable_checks)

    detection_coverage = (
        round((len(detected_checks) / total_checks) * 100, 2)
        if total_checks > 0
        else 0.0
    )

    # Step 4: Find the latest Blue AI mitigation record.
    result = await db.execute(
        select(TelemetryLog)
        .where(
            TelemetryLog.simulation_id == simulation_id,
            TelemetryLog.event_type == "mitigation",
            TelemetryLog.source == "Blue AI"
        )
        .order_by(desc(TelemetryLog.id))
        .limit(1)
    )

    latest_blue_log = result.scalar_one_or_none()

    # Only use a Blue AI record created after the latest Red AI scan.
    # An older mitigation must not be treated as a response to a newer scan.
    blue_log = (
        latest_blue_log
        if latest_blue_log is not None
        and latest_blue_log.id > red_log.id
        else None
    )

    # Step 5: Calculate the security posture.
    # Use the latest Blue verification if it is newer than the Red scan.
    if blue_log is not None:
        verification = (
            blue_log.payload.get("verification", {}) or {}
        )

        posture_data = verification
    else:
        posture_data = red_data

    present = posture_data.get("headers_present", 0)
    total = posture_data.get("total_headers_checked", 0)

    try:
        present = int(present)
        total = int(total)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid security header count in telemetry"
        )

    if total < 0 or present < 0 or present > total:
        raise HTTPException(
            status_code=400,
            detail="Inconsistent security header counts in telemetry"
        )

    security_posture = (
        round((present / total) * 100, 2)
        if total > 0
        else 0.0
    )

    # Step 6: Calculate mitigation success rate.
    if blue_log is not None:
        applied = (
            blue_log.payload.get("applied_mitigations", []) or []
        )
        successful = (
            blue_log.payload.get("successfully_applied", []) or []
        )

        if not isinstance(applied, list) or not isinstance(successful, list):
            raise HTTPException(
                status_code=400,
                detail="Invalid Blue AI mitigation telemetry"
            )

        mitigation_success_rate = (
            round((len(successful) / len(applied)) * 100, 2)
            if len(applied) > 0
            else None
        )
    else:
        applied = []
        successful = []
        mitigation_success_rate = None

    # Step 7: Calculate the weighted Purple AI score.
    # Weights: Security Posture 50%, Check Coverage 25%,
    # Mitigation Success Rate 25%.
    #
    # If there is no fresh mitigation record, normalize the score
    # using only the available 75% of the weights.
    weighted_total = (
        security_posture * 0.50
        + detection_coverage * 0.25
    )

    available_weight = 0.75

    if mitigation_success_rate is not None:
        weighted_total += mitigation_success_rate * 0.25
        available_weight = 1.0

    overall_score = (
        round(weighted_total / available_weight, 2)
        if available_weight > 0
        else 0.0
    )

    # Step 8: Assign a rating.
    if overall_score >= 90:
        rating = "Excellent"
    elif overall_score >= 75:
        rating = "Good"
    elif overall_score >= 50:
        rating = "Moderate"
    else:
        rating = "Poor"

    # Step 9: Prepare the Purple AI result.
    purple_result = {
        "status": "completed",
        "target": "arena-web",
        "action": "Security posture and mitigation evaluation",
        "overall_score": overall_score,
        "rating": rating,
        "scoring_weights": {
            "security_posture": 50,
            "detection_coverage": 25,
            "mitigation_success_rate": 25
        },
        "active_weight_total": round(available_weight * 100, 2),
        "metrics": {
            "security_posture": {
                "score": security_posture,
                "weight": 50
            },
            "detection_coverage": {
                "score": detection_coverage,
                "weight": 25
            },
            "mitigation_success_rate": {
                "score": mitigation_success_rate,
                "weight": 25
            }
        },
        "statistics": {
            "total_applicable_security_checks": total_checks,
            "checks_with_valid_results": len(detected_checks),
            "headers_present": present,
            "headers_checked": total,
            "mitigations_attempted": len(applied),
            "mitigations_successful": len(successful)
        },
        "based_on_telemetry": {
            "red_ai_telemetry_id": red_log.id,
            "blue_ai_telemetry_id": (
                blue_log.id if blue_log is not None else None
            )
        },
        "limitations": [
            "Check coverage measures valid security-header check results, not detection of real attacks",
            "Threat Detection Time is not yet implemented",
            "Threat Mitigation Time is not yet implemented",
            "The current score evaluates security headers only"
        ]
    }

    # Step 10: Save Purple AI telemetry and broadcast it through SSE.
    log = await save_telemetry(
        db,
        simulation_id,
        "purple_score",
        "Purple AI",
        purple_result
    )

    # Step 11: Return the scoring result.
    return {
        "message": "Purple AI scoring completed",
        "simulation_id": simulation_id,
        "telemetry_id": log.id,
        "result": purple_result
    }


# Real-time telemetry SSE stream
@app.get("/stream/telemetry")
async def stream_telemetry(
    request: Request
):
    async def event_generator():
        queue = await sse_manager.connect()

        try:
            yield 'data: {"message": "Connected to telemetry stream"}\n\n'

            while not await request.is_disconnected():
                try:
                    message = await asyncio.wait_for(
                        queue.get(),
                        timeout=15
                    )

                    yield f"data: {message}\n\n"

                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"

        finally:
            sse_manager.disconnect(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )
