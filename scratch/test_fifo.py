import os
import time
import multiprocessing
import psutil

def infostealer(fifo_path: str) -> None:
    print(f"[Infostealer] Opening {fifo_path}...")
    # This will block until a writer connects
    try:
        with open(fifo_path, "r") as f:
            print("[Infostealer] Reading data...")
            data = f.read()
            print(f"[Infostealer] Data read: {data}")
    except Exception as e:
        print(f"[Infostealer] Error: {e}")

def deceptenv(fifo_path: str, child_pid: int) -> None:
    print("[DeceptEnv] Starting scanning...")
    time.sleep(1) # Give child time to block
    found_pid = None
    
    # Scan all processes for the FIFO
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.pid == os.getpid(): continue
            for fd in p.open_files():
                if fd.path == os.path.abspath(fifo_path):
                    found_pid = p.pid
                    print(f"[DeceptEnv] Found PID {found_pid} accessing canary!")
                    break
            if found_pid: break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if found_pid:
        print(f"[DeceptEnv] Sending SIGSTOP to {found_pid}")
        os.kill(found_pid, 19) # SIGSTOP
        time.sleep(1)
        
        # Now we can safely kill it or unblock it
        print("[DeceptEnv] Terminating blocked process.")
        os.kill(found_pid, 9) # SIGKILL
    else:
        print("[DeceptEnv] Failed to find PID!")

if __name__ == "__main__":
    fifo_path = "test_canary.honey"
    if os.path.exists(fifo_path):
        os.remove(fifo_path)
    os.mkfifo(fifo_path)
    
    p = multiprocessing.Process(target=infostealer, args=(fifo_path,))
    p.start()
    
    if p.pid is not None:
        deceptenv(fifo_path, p.pid)
    
    p.join()
    os.remove(fifo_path)
