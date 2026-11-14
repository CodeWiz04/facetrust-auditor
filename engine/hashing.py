import hashlib
import json

def canonical_json(obj)->str:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",",":"),
        ensure_ascii=True,
        allow_nan=False,
        
    )

def sha256_hex(data:bytes | str)->str:
    if isinstance(data,str):
        data=data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def config_hash(config:dict)->str:
    return sha256_hex(canonical_json(config))

def hash_input(data:bytes)->str:
    return "sha256:"+sha256_hex(data)

    