import math, socket, sys, argparse, time
from threading import Thread, Lock

common_ports =  [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
                143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 993, 995, 1080,
                1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]

open_ports = []
response_times = []
lock = Lock()

start = time.time()

def valid_ports(ports_list):
    valids = []
    for port in ports_list:
        if port < 1 or port > 65535:
            print("Ports must be in range [1-65535]!")
            sys.exit(1)
        valids.append(port)
    return valids

def valid_range(ports_range):
    valids = []
    try:
        start, stop = map(int, ports_range.split("-"))
        if start < 1 or stop > 65535:
            print("Ports must be in range [1-65535]!")
            sys.exit(1)
    except ValueError:
        print("Invalid range! (python3 port_scanner.py [ip] -r [start-stop])")
        sys.exit(1)
    for port in range(start, stop+1):
        valids.append(port)
    return valids


def threads_calc(length, max_threads):
    return int(min(max(1, math.sqrt(length)), max_threads))

def get_timeout():
    if not response_times:
        return 1.0
    avg = sum(response_times)/len(response_times)
    return max(0.5, min(avg*2.0, 3.0))

def scan_range(ip, ports):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(get_timeout())
            start = time.time()
            if sock.connect_ex((ip, port)) == 0:
                print(f"[{port}]", end=" ", flush=True)
                with lock:
                    open_ports.append(port)
            duration = time.time() - start
            if duration <= 7.5:
                with lock:
                    response_times.append(duration)
                    response_times[:] = response_times[-10:]
            sock.close()

def port_scan(ip, ports=common_ports):
    common_in_range = [common for common in common_ports if common in ports]
    ports = [port for port in ports if port not in common_in_range]

    threads = []
    threads_count =  threads_calc(len(ports)+len(common_in_range), args.max_threads)

    chunk_size = int((len(ports)+len(common_in_range))/threads_count)

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

    ports = []

    parser = argparse.ArgumentParser(prog="Port Scanner", description="Simple python TCP port scanner")
    parser.add_argument("ip")
    parser.add_argument("-r", "--range", default=None, type=valid_range, help="Scan ports in the given range")
    parser.add_argument("-p", "--ports", default=None, type=int, nargs="+", help="Scan the given port list")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t","--max-threads", metavar="max_threads", default=100, type=int, help="Max number of threads to use during the scam")

    args = parser.parse_args()

    if args.range:
        for port in args.range:
            ports.append(port)
    if args.ports:
        for port in valid_ports(args.ports):
            if port not in ports:
                ports.append(port)

    ip = args.ip

    print("Open ports: ", end="", flush=True)

    if ports:
        port_scan(ip, ports)
    else:
        port_scan(ip)

    print(f"\nNumber of open ports: {len(open_ports)}")
    print(f"Scan duration (in seconds): {(time.time()-start):.3f}")