import psutil

def get_current_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append(proc.info)
    return processes

print(get_current_processes())