import hashlib

# Mapping dictionary for known/simulated attack ranges
KNOWN_IP_GEOS = {
    '198.51.100.101': {'country': 'United Kingdom', 'city': 'London'},
    '203.0.113.50': {'country': 'Japan', 'city': 'Tokyo'},
    '192.0.2.75': {'country': 'Russia', 'city': 'Moscow'},
    '198.51.100.87': {'country': 'Germany', 'city': 'Berlin'},
    '203.0.113.99': {'country': 'United States', 'city': 'New York'},
    '192.0.2.44': {'country': 'France', 'city': 'Paris'},
    '198.51.100.12': {'country': 'Australia', 'city': 'Sydney'},
    '203.0.113.15': {'country': 'Canada', 'city': 'Toronto'},
    '185.220.101.5': {'country': 'Netherlands', 'city': 'Tor Exit Node'}
}

def lookup_geoip(ip_address):
    """
    Offline GeoIP mapper to classify IP addresses.
    Eliminates dependencies on external APIs that could fail due to sandbox/offline status.
    """
    if not ip_address:
        return "Unknown", "Unknown"
        
    # Exact lookup in simulated attack dictionary
    if ip_address in KNOWN_IP_GEOS:
        return KNOWN_IP_GEOS[ip_address]['country'], KNOWN_IP_GEOS[ip_address]['city']
        
    # Standard RFC 1918 Private Ranges Check
    if (ip_address.startswith('127.') or 
        ip_address.startswith('192.168.') or 
        ip_address.startswith('10.') or 
        ip_address.startswith('172.16.') or 
        ip_address.startswith('172.31.') or
        ip_address == 'localhost' or 
        ip_address == '::1'):
        return 'Internal Network', 'Local Subnet'
        
    # Deterministic mapping for seed logs to create rich visualization datasets
    hasher = int(hashlib.md5(ip_address.encode('utf-8')).hexdigest(), 16)
    geo_pool = [
        ('United States', 'New York'),
        ('United States', 'San Francisco'),
        ('Germany', 'Frankfurt'),
        ('Japan', 'Tokyo'),
        ('Netherlands', 'Amsterdam'),
        ('United Kingdom', 'London'),
        ('China', 'Beijing'),
        ('Canada', 'Montreal'),
        ('Australia', 'Melbourne'),
        ('Singapore', 'Singapore'),
        ('Russia', 'Saint Petersburg'),
        ('France', 'Marseille'),
        ('India', 'Mumbai'),
        ('Brazil', 'Rio de Janeiro')
    ]
    
    country, city = geo_pool[hasher % len(geo_pool)]
    return country, city
