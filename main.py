#Section 1: Detecting the Operating System
import platform
import logging
from enum import Enum
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

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
        error_msg = f"Unsupported OS: {os_name}. Supported systems: {supported}"
        logger.error(error_msg)
        raise OSDetectionError(error_msg)

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
    
    disks = {}
    try:
        #Section 3: Disk
        disk_parts = psutil.disk_partitions(all=False)
        for partition in disk_parts:
            if partition.fstype in skip_mount_types:
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks[partition.device] = round(usage.percent, 2)
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
    AC = "AC current"
    BATTERY = "Battery"
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
        
        if battery_info.power_plugged:
            status = PoweringStatus.AC
        else:
            status = PoweringStatus.BATTERY
        
        logger.info(f"Current powering method: {status.value}")
        return status
    
    except AttributeError as e:
        #Handle missing attributes in psutil response
        logger.warning(f"Battery info incomplete: {e}. Returning UNKNOWN status")
        return PoweringStatus.UNKNOWN
    
    except Exception as e:
        logger.error(f"Failed to read powering method: {e}", exc_info=True)
        return PoweringStatus.UNKNOWN
    
#print(extract_power_status().value)

#Section 4: processes control (which is the status of some processes?)