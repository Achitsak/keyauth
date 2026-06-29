def envelope(ok: bool, code: str, data=None, message: str = "") -> dict:
    return {"ok": ok, "code": code, "data": data, "message": message}


def ok_env(data=None) -> dict:
    return envelope(True, "ok", data, "")


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
