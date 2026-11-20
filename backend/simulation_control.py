import asyncio
from dataclasses import dataclass, field


@dataclass
class SimulationControl:
    run_event: asyncio.Event = field(
        default_factory=asyncio.Event
    )

    abort_event: asyncio.Event = field(
        default_factory=asyncio.Event
    )


SIMULATION_CONTROLS: dict[int, SimulationControl] = {}

SIMULATION_TASKS: dict[int, asyncio.Task] = {}

SIMULATION_LIFECYCLE_LOCK = asyncio.Lock()


class SimulationAborted(Exception):
    """Raised when a simulation receives an abort signal."""


async def wait_for_simulation_resume(
    control: SimulationControl
) -> None:
    await control.run_event.wait()

    if control.abort_event.is_set():
        raise SimulationAborted(
            "Simulation aborted by an authorized user"
        )


def create_simulation_control(
    simulation_id: int
) -> SimulationControl:
    control = SimulationControl()
    control.run_event.set()

    SIMULATION_CONTROLS[simulation_id] = control

    return control
