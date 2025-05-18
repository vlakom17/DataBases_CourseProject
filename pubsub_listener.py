from app.redis_store import rdb

def listen_to_purchase_events():
    pubsub = rdb.pubsub()
    pubsub.subscribe("pr_events")
    print("Subscribed to Redis channel 'pr_events'. Listening...")

    for message in pubsub.listen():
        if message["type"] == "message":
            print(f"[EVENT] {message['data']}")

if __name__ == "__main__":
    listen_to_purchase_events()
