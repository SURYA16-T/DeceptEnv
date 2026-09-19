import time
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class LoggingEventHandler(FileSystemEventHandler):
    def on_any_event(self, event: Any) -> None:
        print(f"EVENT: {event.event_type} on {event.src_path}")


if __name__ == "__main__":
    observer = Observer()
    handler = LoggingEventHandler()
    observer.schedule(handler, path=".", recursive=False)
    observer.start()
    try:
        with open("test_file.txt", "w") as f:
            f.write("test")
        time.sleep(1)
        print("Reading file...")
        with open("test_file.txt", "r") as f:
            content = f.read()
        time.sleep(1)
    finally:
        observer.stop()
        observer.join()
