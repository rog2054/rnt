from datetime import datetime

def format_datetime_with_ordinal(value):
    '''
    Re-format a datetime string to 'nnth mmm yyyy hh:mm' format
    eg: 17th April 2025 13:56
    '''
    if not isinstance(value, datetime):
        return value
    day = value.day
    suffix = 'th' if 10 <= day % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    return value.strftime(f'{day}{suffix} %B %Y %H:%M')

# logger_registry.py
netmiko_logger = None

def set_netmiko_logger(logger):
    """Store the Netmiko logger globally."""
    global netmiko_logger
    netmiko_logger = logger

def get_netmiko_logger():
    """Retrieve the Netmiko logger."""
    if netmiko_logger is None:
        raise RuntimeError("Netmiko logger not initialized")
    return netmiko_logger