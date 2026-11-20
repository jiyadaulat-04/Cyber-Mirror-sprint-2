import os
import sentry_sdk
import asyncio
import jwt

from pathlib import Path

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    status
)
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, desc
from sqlalchemy.exc import IntegrityError

from database import AsyncSessionLocal
from models import Simulation, TelemetryLog, User
from red_ai import run_reconnaissance
from blue_ai_config import update_nginx_config
from sse_manager import sse_manager

from simulation_control import (
    SIMULATION_CONTROLS,
    SIMULATION_TASKS,
    SIMULATION_LIFECYCLE_LOCK,
    SimulationAborted,
    create_simulation_control,
    wait_for_simulation_resume
)
from security import (
    decode_access_token,
    verify_password,
    hash_password,
    create_access_token
)

if os.getenv("SENTRY_DSN"):
    sentry_sdk.init(
        dsn=os.environ["SENTRY_DSN"],
        send_default_pii=False,
        traces_sample_rate=0.1,
    )
app = FastAPI(
    title="Cyber Mirror API",
    description="Cyber Mirror Sprint 2 Backend",
    version="1.1.0"
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


# Authentication: clients must send Authorization: Bearer <JWT>.
bearer_scheme = HTTPBearer(auto_error=False)


# Database connection
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


# Request schemas
class SimulationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)


class TelemetryCreate(BaseModel):
    simulation_id: int = Field(gt=0)
    event_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    payload: dict = Field(default_factory=dict)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_.-]+$"
    )
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(pattern=r"^(analyst|viewer)$")


# JWT authentication dependency
async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload.get("sub", ""))
    except (jwt.InvalidTokenError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = await db.get(User, user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is unavailable",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


# Role-based access control dependency factory
def require_roles(*allowed_roles: str):
    async def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action"
            )
        return current_user

    return role_checker


# Blue AI configuration file shared with the Arena container
BLUE_AI_CONFIG_PATH = Path(
    "/app/arena/security-headers.conf"
)

BLUE_AI_CONFIG_LOCK = asyncio.Lock()


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


# Public home route
@app.get("/")
async def home():
    return {
        "message": "Cyber Mirror Backend is running!",
        "status": "success"
    }


# Public health check (does not expose database details)
@app.get("/health")
async def health():
    return {"status": "healthy"}


# Login and issue a short-lived JWT access token
@app.post("/auth/login")
async def login(
    data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    username = data.username.strip().lower()

    result = await db.execute(
        select(User).where(User.username == username)
    )
    user = result.scalar_one_or_none()

    # Use the same response for unknown usernames and wrong passwords.
    if (
        user is None
        or not user.is_active
        or not verify_password(data.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = create_access_token(user.id)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }


# Return the identity and role represented by the current token
@app.get("/auth/me")
async def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "is_active": current_user.is_active
    }


# Admin-only account provisioning. Public registration is intentionally disabled.
@app.post("/auth/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin"))
):
    username = data.username.strip().lower()

    result = await db.execute(
        select(User).where(User.username == username)
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )

    user = User(
        username=username,
        password_hash=hash_password(data.password),
        role=data.role,
        is_active=True
    )

    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )

    await db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active
    }


# Database health check: Admin only
@app.get("/db-health")
async def db_health(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin"))
):
    await db.execute(text("SELECT 1"))
    return {"database": "connected"}


# Create simulation: Admin and Analyst
@app.post("/simulations")
async def create_simulation(
    data: SimulationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst"))
):
    simulation = Simulation(name=data.name.strip())

    db.add(simulation)
    await db.commit()
    await db.refresh(simulation)

    return {
        "id": simulation.id,
        "name": simulation.name,
        "status": simulation.status
    }


# Get all simulations: any authenticated role
@app.get("/simulations")
async def get_simulations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
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


# Create a telemetry log manually: Admin and Analyst
@app.post("/telemetry")
async def create_telemetry(
    data: TelemetryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst"))
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


# Get telemetry logs for a simulation: any authenticated role
@app.get("/simulations/{simulation_id}/telemetry")
async def get_telemetry(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
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


# Run Red AI reconnaissance: Admin and Analyst
@app.post("/red-ai/run")
async def run_red_ai(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst"))
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


# Blue AI automated mitigation: Admin and Analyst
@app.post("/blue-ai/mitigate")
async def run_blue_ai(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst"))
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
        blue_result = {
            "status": "no_action_required",
            "target": "arena-web",
            "action": "No mitigation required",
            "applied_mitigations": [],
            "successfully_applied": [],
            "missing_headers": missing_headers
        }

        log = await save_telemetry(
            db,
            simulation_id,
            "mitigation",
            "Blue AI",
            blue_result
        )

        return {
            "message": "No approved mitigations required",
            "simulation_id": simulation_id,
            "telemetry_id": log.id,
            "status": "no_action_required",
            "result": blue_result
        }

    # Step 5: Safely update the shared Nginx configuration.
    # The lock prevents concurrent writes within this backend process.
    async with BLUE_AI_CONFIG_LOCK:
        try:
            update_nginx_config(
                BLUE_AI_CONFIG_PATH,
                selected_mitigations,
                APPROVED_MITIGATIONS
            )
        except OSError as error:
            raise HTTPException(
                status_code=500,
                detail=f"Unable to update mitigation configuration: {error}"
            )

        # Step 6: Allow the Arena Nginx watcher to detect and reload.
        await asyncio.sleep(5)

        # Step 7: Verify the mitigation by running Red AI again.
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


# Purple AI scoring engine: Admin and Analyst
@app.post("/purple-ai/score")
async def run_purple_ai(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst"))
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
    blue_log = (
        latest_blue_log
        if latest_blue_log is not None
        and latest_blue_log.id > red_log.id
        else None
    )

    # Step 5: Calculate the security posture.
    if blue_log is not None:
        blue_payload = blue_log.payload or {}

        if blue_payload.get("status") == "no_action_required":
            posture_data = red_data
        else:
            verification = blue_payload.get("verification")

            if (
                not isinstance(verification, dict)
                or verification.get("status") != "completed"
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Blue AI mitigation verification is missing or incomplete"
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


# Authenticated real-time telemetry SSE stream.
# The frontend must use fetch() with an Authorization header (native EventSource
# does not support custom Authorization headers).
@app.get("/stream/telemetry")
async def stream_telemetry(
    request: Request,
    current_user: User = Depends(get_current_user)
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



# ==========================================================
# SIMULATION LIFECYCLE MANAGEMENT
# ==========================================================

async def update_simulation_status(
    simulation_id: int,
    new_status: str
):
    async with AsyncSessionLocal() as db:

        result = await db.execute(
            select(Simulation).where(
                Simulation.id == simulation_id
            )
        )

        simulation = result.scalar_one_or_none()

        if simulation is not None:
            simulation.status = new_status
            await db.commit()


async def simulation_checkpoint(
    simulation_id: int,
    control
):
    if control.abort_event.is_set():
        raise SimulationAborted()

    if not control.run_event.is_set():

        await update_simulation_status(
            simulation_id,
            "paused"
        )

        await control.run_event.wait()

        if control.abort_event.is_set():
            raise SimulationAborted()

        await update_simulation_status(
            simulation_id,
            "running"
        )


async def execute_simulation_workflow(
    simulation_id: int,
    actor_id: int,
    control
):

    try:

        async with AsyncSessionLocal() as db:

            user_result = await db.execute(
                select(User).where(User.id == actor_id)
            )

            actor = user_result.scalar_one_or_none()

            if actor is None or not actor.is_active:
                raise RuntimeError(
                    "Simulation owner is no longer active"
                )

            simulation_result = await db.execute(
                select(Simulation).where(
                    Simulation.id == simulation_id
                )
            )

            simulation = simulation_result.scalar_one_or_none()

            if simulation is None:
                raise RuntimeError(
                    "Simulation no longer exists"
                )

            # PHASE 1: RED AI
            await simulation_checkpoint(
                simulation_id,
                control
            )

            await run_red_ai(
                simulation_id,
                db,
                actor
            )

            # PHASE 2: BLUE AI
            await simulation_checkpoint(
                simulation_id,
                control
            )

            await run_blue_ai(
                simulation_id,
                db,
                actor
            )

            # PHASE 3: PURPLE AI
            await simulation_checkpoint(
                simulation_id,
                control
            )

            await run_purple_ai(
                simulation_id,
                db,
                actor
            )

            await simulation_checkpoint(
                simulation_id,
                control
            )

            simulation.status = "completed"
            await db.commit()

    except SimulationAborted:

        await update_simulation_status(
            simulation_id,
            "aborted"
        )

    except Exception as error:

        print(
            f"Simulation {simulation_id} failed: {error}"
        )

        await update_simulation_status(
            simulation_id,
            "failed"
        )

    finally:

        async with SIMULATION_LIFECYCLE_LOCK:

            SIMULATION_TASKS.pop(
                simulation_id,
                None
            )

            SIMULATION_CONTROLS.pop(
                simulation_id,
                None
            )


# START SIMULATION
@app.post("/simulations/{simulation_id}/start")
async def start_simulation(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    )
):

    async with SIMULATION_LIFECYCLE_LOCK:

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

        if simulation.status != "created":
            raise HTTPException(
                status_code=409,
                detail=(
                    "Only newly created simulations "
                    "can be started"
                )
            )

        if simulation_id in SIMULATION_TASKS:
            raise HTTPException(
                status_code=409,
                detail="Simulation is already active"
            )

        control = create_simulation_control(
            simulation_id
        )

        simulation.status = "running"
        await db.commit()

        task = asyncio.create_task(
            execute_simulation_workflow(
                simulation_id,
                current_user.id,
                control
            )
        )

        SIMULATION_TASKS[simulation_id] = task

    return {
        "message": "Simulation workflow started",
        "simulation_id": simulation_id,
        "status": "running",
        "workflow": [
            "Red AI",
            "Blue AI",
            "Purple AI"
        ]
    }


# PAUSE SIMULATION
@app.post("/simulations/{simulation_id}/pause")
async def pause_simulation(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    )
):

    control = SIMULATION_CONTROLS.get(
        simulation_id
    )

    if control is None:
        raise HTTPException(
            status_code=409,
            detail="No active simulation workflow"
        )

    if control.abort_event.is_set():
        raise HTTPException(
            status_code=409,
            detail="Simulation is being aborted"
        )

    control.run_event.clear()

    return {
        "message": "Pause requested",
        "simulation_id": simulation_id,
        "status": "pause_requested",
        "detail": (
            "The current AI phase will finish "
            "before the workflow pauses."
        )
    }


# RESUME SIMULATION
@app.post("/simulations/{simulation_id}/resume")
async def resume_simulation(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    )
):

    control = SIMULATION_CONTROLS.get(
        simulation_id
    )

    if control is None:
        raise HTTPException(
            status_code=409,
            detail="No paused workflow exists"
        )

    if control.abort_event.is_set():
        raise HTTPException(
            status_code=409,
            detail="Simulation is being aborted"
        )

    control.run_event.set()

    return {
        "message": "Resume requested",
        "simulation_id": simulation_id,
        "status": "running"
    }


# ABORT SIMULATION
@app.post("/simulations/{simulation_id}/abort")
async def abort_simulation(
    simulation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    )
):

    control = SIMULATION_CONTROLS.get(
        simulation_id
    )

    if control is None:
        raise HTTPException(
            status_code=409,
            detail="No active workflow to abort"
        )

    control.abort_event.set()
    control.run_event.set()

    return {
        "message": "Abort requested",
        "simulation_id": simulation_id,
        "status": "abort_requested"
    }


# ADMIN EMERGENCY KILL SWITCH
@app.post("/simulations/kill-switch")
async def simulation_kill_switch(
    current_user: User = Depends(
        require_roles("admin")
    )
):

    aborted_ids = []

    for simulation_id, control in list(
        SIMULATION_CONTROLS.items()
    ):

        control.abort_event.set()
        control.run_event.set()

        aborted_ids.append(simulation_id)

    return {
        "message": "Emergency kill switch activated",
        "requested_aborts": len(aborted_ids),
        "simulation_ids": aborted_ids,
        "status": "abort_requested"
    }




# ============================================================
# MILESTONE 6: DASHBOARD ANALYTICS API
# ============================================================

@app.get("/analytics/overview")
async def get_analytics_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Fetch all simulations
    simulation_result = await db.execute(
        select(Simulation)
    )

    simulations = simulation_result.scalars().all()

    # Fetch all telemetry records
    telemetry_result = await db.execute(
        select(TelemetryLog).order_by(TelemetryLog.id.desc())
    )

    telemetry = telemetry_result.scalars().all()

    # Simulation status counts
    status_counts = {
        "created": 0,
        "running": 0,
        "paused": 0,
        "completed": 0,
        "aborted": 0,
        "failed": 0
    }

    for simulation in simulations:
        current_status = simulation.status.lower()

        if current_status in status_counts:
            status_counts[current_status] += 1

    # Telemetry counts
    red_ai_scans = 0
    threats_detected = 0
    blue_ai_actions = 0
    purple_ai_evaluations = 0

    successful_mitigations = 0
    no_action_required = 0

    purple_scores = []

    for log in telemetry:
        payload = log.payload or {}

        if log.event_type == "reconnaissance":
            red_ai_scans += 1
            missing_headers = payload.get("missing_security_headers", [])
            if isinstance(missing_headers, list):
                threats_detected += len(missing_headers)

        elif log.event_type == "mitigation":
            blue_ai_actions += 1

            if payload.get("status") == "no_action_required":
                no_action_required += 1

            applied = payload.get("successfully_applied", [])

            if isinstance(applied, list):
                successful_mitigations += len(applied)

        elif log.event_type == "purple_score":
            purple_ai_evaluations += 1

            score = payload.get("overall_score")

            if (
                isinstance(score, (int, float))
                and not isinstance(score, bool)
                and 0 <= score <= 100
            ):
                purple_scores.append(float(score))

    average_security_score = (
        round(sum(purple_scores) / len(purple_scores), 2)
        if purple_scores else None
    )

    return {
        "total_simulations": len(simulations),
        "simulation_status": status_counts,
        "total_telemetry": len(telemetry),
        "red_ai_scans": red_ai_scans,
        "threats_detected": threats_detected,
        "blue_ai_actions": blue_ai_actions,
        "successful_mitigations": successful_mitigations,
        "no_action_required": no_action_required,
        "purple_ai_evaluations": purple_ai_evaluations,
        "average_security_score": average_security_score,
        "valid_security_scores": len(purple_scores)
    }


# ============================================================
# MILESTONE 6: ANALYTICS HISTORY API
# ============================================================

@app.get("/analytics/history")
async def get_analytics_history(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    result = await db.execute(
        select(TelemetryLog).order_by(TelemetryLog.created_at.asc())
    )

    telemetry = result.scalars().all()

    security_score_trend = []
    red_ai_history = []
    blue_ai_history = []

    for log in telemetry:

        payload = log.payload or {}

        timestamp = (
            log.created_at.isoformat()
            if log.created_at else None
        )

        if (
            log.event_type == "purple_score"
            and log.source == "Purple AI"
        ):

            score = payload.get("overall_score")

            if (
                isinstance(score, (int, float))
                and not isinstance(score, bool)
                and 0 <= score <= 100
            ):
                security_score_trend.append({
                    "telemetry_id": log.id,
                    "simulation_id": log.simulation_id,
                    "timestamp": timestamp,
                    "score": float(score),
                    "rating": payload.get("rating", "Unknown")
                })

        elif (
            log.event_type == "reconnaissance"
            and log.source == "Red AI"
        ):

            red_ai_history.append({
                "telemetry_id": log.id,
                "simulation_id": log.simulation_id,
                "timestamp": timestamp,
                "status": payload.get("status", "unknown"),
                "headers_present": payload.get("headers_present", 0),
                "headers_missing": payload.get("headers_missing", 0),
                "http_status": payload.get("http_status")
            })

        elif (
            log.event_type == "mitigation"
            and log.source == "Blue AI"
        ):

            applied = payload.get("applied_mitigations", [])
            successful = payload.get("successfully_applied", [])

            if not isinstance(applied, list):
                applied = []

            if not isinstance(successful, list):
                successful = []

            blue_ai_history.append({
                "telemetry_id": log.id,
                "simulation_id": log.simulation_id,
                "timestamp": timestamp,
                "status": payload.get("status", "unknown"),
                "mitigations_attempted": len(applied),
                "mitigations_successful": len(successful)
            })

    recent_telemetry = []

    for log in reversed(telemetry[-20:]):

        payload = log.payload or {}

        recent_telemetry.append({
            "id": log.id,
            "simulation_id": log.simulation_id,
            "event_type": log.event_type,
            "source": log.source,
            "status": payload.get("status", "logged"),
            "target": payload.get("target"),
            "created_at": (
                log.created_at.isoformat()
                if log.created_at else None
            )
        })

    return {
        "security_score_trend": security_score_trend,
        "red_ai_history": red_ai_history,
        "blue_ai_history": blue_ai_history,
        "recent_telemetry": recent_telemetry
    }

