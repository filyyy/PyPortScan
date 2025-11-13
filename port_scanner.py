import math
import socket
import sys
from threading import Thread, Lock

common_ports =  [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
                143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 993, 995, 1080,
                1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]

open_ports = []
lock = Lock()


def threads_calc(length, bal=20, max_threads=100):
    return int(min(max(1, math.sqrt(length)), max_threads))

def get_timeout(port):
    if port in common_ports:
        return 0.8
    elif port < 1024:
        return 1.2
    else:
        return 1.8

def scan_range(ip, ports):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(get_timeout(port))
            if sock.connect_ex((ip, port)) == 0:
                print(f"[{port}]", end=" ", flush=True)
                with lock:
                    open_ports.append(port)
            sock.close()

def port_scan(ip, common_in_range, ports):
    ports = [port for port in ports if port not in common_ports]
    threads = []
    threads_count =  threads_calc(len(ports)+len(common_ports))
    chunk_size = int((len(ports)+len(common_ports))/threads_count)

    for ports_chunk in list(common_in_range[i:i+chunk_size] for i in range(0,len(common_in_range),chunk_size)):
        t = Thread(target=scan_range, args=(ip, ports_chunk))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    
    threads.clear()

    for ports_chunk in list(ports[i:i+chunk_size] for i in range(0,len(ports),chunk_size)):
        t = Thread(target=scan_range, args=(ip, ports_chunk))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Specify the target ip! (python3 multithread_port_scanner.py [ip] [start-stop]")
        sys.exit(1)

    if len(sys.argv) == 3:
        try:
            start, stop = map(int, sys.argv[2].split("-"))
        except ValueError:
            print("Invalid range! (python3 multithread_port_scanner.py [ip] [start-stop])")
            sys.exit(1)
        ports = list(range(start, stop + 1))
    elif len(sys.argv) == 2:
        ports = common_ports

    ip = sys.argv[1]
    common_in_range = [common for common in common_ports if common in ports]
    ports = [port for port in ports if port not in common_in_range]

    print("Open ports: ", end="", flush=True)

    port_scan(ip, common_in_range, ports)

    print(f"\nNumber of open ports: {len(open_ports)}")