import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])
EVALUATION_RESULTS_PATH = (
    Path(__file__).resolve().parents[2]
    / "evaluation"
    / "results"
    / "evaluation.json"
)


@router.get("/results", response_model=None)
def evaluation_results() -> JSONResponse:
    """Return the last locally generated evaluation result without running it."""
    try:
        with EVALUATION_RESULTS_PATH.open("r", encoding="utf-8") as result_file:
            payload: Any = json.load(result_file)
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation results are not available. Run the local evaluation first.",
        ) from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored evaluation results could not be read.",
        ) from error

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored evaluation results have an invalid format.",
        )
    return JSONResponse(content=payload)
