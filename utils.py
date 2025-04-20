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
