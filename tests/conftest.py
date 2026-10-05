from pathlib import Path

import pytest

from dataspace import DataSpace
from dataspace.catalog import DatasetMetadata
from dataspace.identity import Participant, Role
from dataspace.policy import Constraint, Duty, Rule, RuleType

PARTICIPANTS_DIR = Path(__file__).resolve().parent.parent / "participants"


def make_participant(pid: str = "p1", **attributes) -> Participant:
    return Participant(
        id=pid, name=pid, organization=pid, public_key="unused",
        roles={Role.PROVIDER, Role.CONSUMER}, attributes=attributes,
    )


@pytest.fixture
def space():
    """Provider (FR hospital), EU consumer (DE lab), non-EU consumer (US company)."""
    space = DataSpace()
    space.join("hospital", "Hospital", "Hospital", ["provider"], {"country": "FR"})
    space.join("lab", "Lab", "Lab", ["consumer"], {"country": "DE"})
    space.join("corp", "Corp", "Corp", ["consumer"], {"country": "US"})
    space.publish_dataset(
        "hospital",
        "records",
        b"id,value\n1,42\n",
        DatasetMetadata(title="Clinical records", keywords=["health"], sensitivity="confidential"),
        [
            Rule(
                id="eu-research",
                actions=["read", "analyze"],
                constraints=[
                    Constraint(left_operand="participant.country", operator="in", right_operand=["FR", "DE"]),
                    Constraint(left_operand="purpose", operator="eq", right_operand="research"),
                ],
                duties=[Duty(action="delete_after", parameters={"days": 30})],
            ),
            Rule(id="no-share", type=RuleType.PROHIBITION, actions=["share"]),
        ],
    )
    return space
