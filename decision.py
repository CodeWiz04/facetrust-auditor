import math
import time
import uuid
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone

from . import ENGINE_VERSION
from .errors import EngineError

STAGES={"consent","embedding","threshold","subgroup","liveness","deletion"}
STATUSES={"completed","rejected","flagged"}
SEVERITIES=("info","low","medium","high","critical")

class Timer:
    def __init__(self):
        self.start=time.perf_counter()

    def ms(self)->float:
        return round((time.perf_counter()-self.start)*1000,3)
        