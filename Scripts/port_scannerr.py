# Port Scanner
import concurrent
import concurrent.futures
import socket
import argparse

def main():

    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("--host", required=True)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=100)
    args = parser.parse_args()

    host = args.host
    start = args.start
    end = args.end
    timeout = args.timeout
    workers = args.workers

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as thread:
        futures = {thread.submit(scan_port, host, port, timeout): port for port in range(start, end + 1)}
    
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                print(f"[+] Port {port} is open")


def scan_port(host, port, timeout) -> bool:
    try:    
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        result = conn.connect_ex((host, port))
        return result == 0
    except:
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    main()