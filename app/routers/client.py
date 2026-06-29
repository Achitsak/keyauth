import time

from fastapi import APIRouter

from ..envelope import ok_env

router = APIRouter(prefix="/api/v1")


@router.get("/meta/health")
def health():
    return ok_env({"status": "alive"})


@router.get("/meta/time")
def server_time():
    return ok_env({"ts": int(time.time())})
