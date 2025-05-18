import redis
from datetime import timedelta

def init_redis_connection():
    return redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

rdb = init_redis_connection()


def save_auth_token(user_id: int, token: str, hours=24):
    rdb.setex(f"auth_token:{user_id}", timedelta(hours=hours), token)

def get_auth_token(user_id: int):
    return rdb.get(f"auth_token:{user_id}")

def delete_auth_token(user_id: int):
    rdb.delete(f"auth_token:{user_id}")



def set_listing_status(listing_id: int, status: str):
    rdb.set(f"listing_status:{listing_id}", status)

def get_listing_status(listing_id: int):
    return rdb.get(f"listing_status:{listing_id}")

def delete_listing_status(listing_id: int):
    rdb.delete(f"listing_status:{listing_id}")


def set_purchase_request_status(request_id: int, status: str):
    rdb.hset(f"pr_status:{request_id}", "status", status)

def get_purchase_request_status(request_id: int):
    return rdb.hget(f"pr_status:{request_id}", "status")

def publish_purchase_event(message: str):
    rdb.publish("pr_events", message)
