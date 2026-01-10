#Section 1: Detecting the Operating System
import platform
import logging
from enum import Enum
from typing import Dict, Tuple, Optional
from flask import Flask, render_template, request, redirect, url_for
import os

logger = logging.getLogger(__name__)
FOLLOWED_PROCESSES_FILE = os.path.dirname(os.path.realpath(__file__)) + "\\"+ "prova.txt"

class SupportedOS(Enum):
    """Enumeration of supported operating systems"""
    WINDOWS = 'Windows'
    LINUX = 'Linux'

class OSDetectionError(Exception):
    """Raised when the operating system cannot be detected or is unsupported"""
    pass

def detect_os() -> SupportedOS:
    """
    Detect and validate the current operating system
    
    Returns:
        SupportedOS: The detected operating system enum value.
    
    Raises:
        OSDetectionError: If the OS is unsupported or cannot be detected.
    
    Example:
        >>> os = detect_os()
        >>> if os == SupportedOS.WINDOWS:
        ...     print("Running on Windows")
    """
    os_name = platform.system()

    os_map = {
        'Windows': SupportedOS.WINDOWS,
        'Linux': SupportedOS.LINUX,
    }

    if os_name not in os_map:
        supported = ', '.join(os_map.keys())
        logger.warning(f"Unsupported OS: {os_name}. Supported systems: {supported}. Some features may not work properly")

    detected_os = os_map[os_name]
    logger.info(f"Detected OS: {detected_os.value}")
    return detected_os

#print(detect_os())

#Section 2: extracting CPU usage and temperature
import psutil

def extract_system_stats(interval: float = 0.1, skip_mount_types: Optional[set] = None) -> Tuple[float, float, Dict[str, float]]:
    """
    Extract CPU, RAM, and disk usage statistics.
    
    Args:
        interval: CPU measurement interval in seconds
        skip_mount_types: Filesystem types to skip (e.g., {'tmpfs', 'devtmpfs'})
    
    Returns:
        Tuple of (cpu_percent, ram_percent, disk_usage_dict)
    """
    if skip_mount_types is None:
        skip_mount_types = {'tmpfs', 'devtmpfs', 'squashfs', 'overlay'}
    
    try:
        #Section 1: CPU
        cpu_perc = psutil.cpu_percent(interval = interval)
    except Exception as e:
        logger.error(f"Failed to get CPU stats: {e}")
        cpu_perc = 0.0
    
    try:
        #Section 2: RAM
        ram_perc = psutil.virtual_memory().percent
    except Exception as e:
        logger.error(f"Failed to get RAM stats: {e}")
        ram_perc = 0.0
    
    disks = []
    try:
        #Section 3: Disk
        disk_parts = psutil.disk_partitions(all=False)
        for partition in disk_parts:
            if partition.fstype in skip_mount_types:
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    'name': partition.device,
                    'usage': round(usage.percent, 1)
                })
            except (PermissionError, OSError) as e:
                logger.debug(f"Skipping {partition.device}: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error reading {partition.device}: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Failed to enumerate disk partitions: {e}")
    
    return cpu_perc, ram_perc, disks

#print(extract_system_stats())

#Section 3: extracting power status
class PoweringStatus(Enum):
    """Enumeration of possible power status"""
    AC = "Power Plugged"
    BATTERY = "Using Battery"
    UNKNOWN = "Unknown"

def extract_power_status() -> PoweringStatus:
    """
    Detect the current power status of the system.

    Returns:
        PoweringStatus: The detected power status (AC, BATTERY, or UNKNOWN)
    """
    try:
        battery_info = psutil.sensors_battery().power_plugged
        
        if battery_info is None:
            logger.debug("No battery detected. Assuming AC power")
            return PoweringStatus.AC
        
        if battery_info:
            status = PoweringStatus.AC
        else:
            status = PoweringStatus.BATTERY
        
        logger.info(f"Current powering method: {status.value}")
        return status
    
    except AttributeError as e:
        #Handle missing attributes in psutil response
        logger.warning(f"Battery9 info incomplete: {e}. Returning UNKNOWN status")
        return PoweringStatus.UNKNOWN
    
    except Exception as e:
        logger.error(f"Failed to read powering method: {e}", exc_info=True)
        return PoweringStatus.UNKNOWN
    
#print(extract_power_status().value)

#Section 4: processes control (which is the status of some processes?)
def get_process_status(pid):
    """
    Get the status of a process by PID
    
    Args:
        pid: Process ID (integer)
    
    Returns:
        str: process status (e.g. 'running', 'sleeping', 'zombie')
        None: if process doesn't exist or access is denied

    Raises:
        ValueError: if pid is invalid
    """
    if not isinstance(pid, int) or pid <= 0:
        raise ValueError(f"Invalid PID: {pid}. Must be a positive integer.")
    
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return p.status()
    
    except psutil.NoSuchProcess:
        logger.debug(f"Process {pid} does not exist")
        return None

    except psutil.AccessDenied:
        logger.warning(f"Access denied to process {pid}")
        return None
    
    except psutil.ZombieProcess:
        logger.debug(f"Process {pid} is a zombie process")
        return psutil.STATUS_ZOMBIE
    
    except Exception as e:
        logger.error(f"Unexpected error reading process {pid}: {type(e).__name__}: {e}")
        return None

def get_pid_from_name(name):
    """
    Find the PID of a process by name.
    
    Args:
        name: process name to search for (matches against name, exe basename, or cmdline)
    
    Returns:
        int: PID of the first matching process
        None: if no matching process found

    Raises:
        ValueError: if name is invalid
    """
    if not name or not isinstance(name, str):
        raise ValueError("name must be a non-empty string")
    
    name = name.strip()
    if not name:
        raise ValueError("name cannot be whitespace only")
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            if info.get('name') == name:
                return info['pid']
            
            if info.get('exe'):
                if os.path.basename(info['exe']) == name:
                    return info['pid']
            
            if info.get('cmdline') and len(info['cmdline']) > 0:
                if info['cmdline'][0] == name:
                    return info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

        except Exception as e:
            logger.warning(f"Errpr checking process: {type(e).__name__}: {e}")
            continue
    
    logger.debug(f"No process found with name: {name}")
    return None

def add_process_to_file(process_name, filename):
    """
    Append a process name to a file
    
    Args:
        process_name: name of the process to add
        filename: path to the file
    
    Returns:
        bool: True if successful, False otherwise

    Raises:
        ValueError: if inputs are invalid
        PermissionError: if file cannot be written
        OSError: if disk is full or other I/O error
    """
    if not process_name or not isinstance(process_name, str):
        raise ValueError("process_name must be a non-empty string")
    
    if not filename or not isinstance(filename, str):
        raise ValueError("filename must be a non-empty string")
    
    process_name = process_name.strip()
    if not process_name:
        raise ValueError("process_name cannot be whitespace only")
    
    if '\n' in process_name or '\r' in process_name:
        raise ValueError("process_name cannot contain newline characters")
    
    try:
        with open(filename, 'a', encoding='utf-8') as file:
            file.write(f"{process_name}\n")
        logger.info(f"Added process '{process_name}' to {filename}")
        return True
    
    except PermissionError:
        logger.error(f"Permission denied writing to file: {filename}")
        raise

    except OSError as e:
        logger.error(f"I/O error writing to {filename}: {e}")
        raise

    except Exception as e:
        logger.error(f"Unexpected error writing process to {filename}: {type(e).__name__}: {e}")
        raise

def remove_process_from_file(process_name, filename):
    """
    Remove a process from a file.

    Args:
        process_name: name of the process to remove
        filename: Path to the file

    Returns:
        bool: True if process was found and removed, False if not found
    
    Raises:
        ValueError: if inputs are invalid
        FileNotFoundError: if file doesn't exist
        PermissionError: if file cannot be read/written
    """
    if not process_name or not isinstance(process_name, str):
        raise ValueError("process_name must be a non-empty string")

    if not filename or not isinstance(filename, str):
        raise ValueError("filename must be a non-empty string")
    
    process_name = process_name.strip()
    if not process_name:
        raise ValueError("process_name cannot be whitespace only")
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file]
        
        if process_name not in lines:
            logger.info(f"Process '{process_name}' not found in {filename}")
            return False
        
        filtered_lines = [line for line in lines if line and line != process_name]

        with open(filename, 'w', encoding='utf-8') as file:
            for line in filtered_lines:
                file.write(f"{line}\n")
        
        logger.info(f"Removed process '{process_name}' from {filename}")
        return True

    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
        raise
    except PermissionError:
        logger.error(f"Permission denied accessing file: {filename}")
        raise
    except OSError as e:
        logger.error(f"I/O error accessing {filename}: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to remove process from file: {e}")
        raise

def get_followed_processes(filename):
    """
    Read process names from a file, one per line.

    Args:
        filename: Path to the file containing process names

    Returns:
        list: List of process names (stripped of whitespace)
    
    Raises:
        ValueError: if filename is invalid
        FileNotFoundError: if file does not exist
        PermissionError: if file cannot be read
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string")
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            processes = [line.strip() for line in file if line.strip()]
        return processes

    except FileNotFoundError:
        logger.error(f"Process list file not found: {filename}")
        raise
    except PermissionError:
        logger.error(f"Permission denied reading file: {filename}")
        raise
    except UnicodeDecodeError:
        logger.error(f"Invalid encoding in file {filename}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error reading process list from {filename}: {type(e).__name__}: {e}")
        raise

def get_current_processes():
    """
    Get list of all running processes with their PID and name.

    Returns:
        list: List of dicts with 'pid' and 'name' keys
    
    Note:
        - May not have access to all processes (permission-dependent)
        - Processes may terminate during iteration
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            logger.warning(f"Unexpected error getting process info: {type(e).__name__}: {e}")
            continue

    return processes

app = Flask(__name__)

@app.route('/')
def index():
    # Render the 'index.html' template
    stats = extract_system_stats()
    cpu_usage = stats[0]
    ram_usage = stats[1]
    disks = stats[2]
    power_status = extract_power_status().value

    followed_processes_list = []
    try:
        process_names = get_followed_processes(FOLLOWED_PROCESSES_FILE)

        for name in process_names:
            pid = get_pid_from_name(name)
            status = None

            if pid:
                status = get_process_status(pid)
            
            followed_processes_list.append({
                'name': name,
                'pid': pid,
                'status': status,
            })
    
    except FileNotFoundError:
        with open(FOLLOWED_PROCESSES_FILE, 'w') as f:
            pass
        followed_processes_list = []
    except Exception as e:
        logger.error(f"Error getting followed processes: {e}")
        followed_processes_list = []
    
    return render_template('main.html',
                           cpu_usage=round(cpu_usage, 1),
                           ram_usage=round(ram_usage, 1),
                           power_status=power_status,
                           disks=disks,
                           followed_processes=followed_processes_list)

@app.route('/settings')
def settings():
    processes = get_current_processes()
    processes.sort(key=lambda x: x['name'].lower())
    try:
        followed = get_followed_processes(FOLLOWED_PROCESSES_FILE)
    except FileNotFoundError:
        with open(FOLLOWED_PROCESSES_FILE, 'w'):
            pass
        followed = []
    except Exception as e:
        logger.error(f"Error reading followed processes: {e}")
        followed = []
    
    return render_template('settings.html',
                           processes=processes,
                           followed_processes=followed,
                           message=request.args.get('message'))

@app.route('/add_processes', methods=['POST'])
def add_processes():
    """Add selected processes to the followed list"""
    selected = request.form.getlist('selected_processes')

    if not selected:
        return redirect(url_for('settings', message='No processes selected to add'))
    
    try:
        existing = get_followed_processes(FOLLOWED_PROCESSES_FILE)
    except FileNotFoundError:
        existing = []
    except Exception as e:
        logger.error(f"Error reading followed processes: {e}")
        return redirect(url_for('settings', message=f"Error: {str(e)}"))
    
    added_count = 0
    skipped_count = 0

    for process_name in selected:
        if process_name in existing:
            skipped_count += 1
            continue
        
        try:
            add_process_to_file(process_name, FOLLOWED_PROCESSES_FILE)
            added_count += 1
            continue
        except Exception as e:
            logger.error(f"Error adding process {process_name}: {e}")
            return redirect(url_for('settings', message=f'Error adding processes: {str(e)}'))
    
    message = f'Added {added_count} process(es)'
    if skipped_count > 0:
        message += f', skipped {skipped_count} duplicate(s)'
    
    return redirect(url_for('settings', message=message))

@app.route('/remove_processes', methods=['POST'])
def remove_processes():
    """Remove selected processes from the followed list"""
    selected = request.form.getlist('selected_processes')

    if not selected:
        return redirect(url_for('settings', message='No processes selected to remove'))
    
    removed_count = 0
    not_found_count = 0

    for process_name in selected:
        try:
            if remove_process_from_file(process_name, FOLLOWED_PROCESSES_FILE):
                removed_count += 1
            else:
                not_found_count += 1
        except Exception as e:
            logger.error(f"Error removing process {process_name}: {e}")
            return redirect(url_for('settings', message=f'Error removing processes: {str(e)}'))
        
    message = f'Removed {removed_count} process(es)'
    if not_found_count > 0:
        message += f', {not_found_count} not found'
    
    return redirect(url_for('settings', message=message))

if __name__ == '__main__':
    detect_os()
    app.run(debug=True, host='0.0.0.0', port=5000)