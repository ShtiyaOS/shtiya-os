# cache.py
# ==============================================================================
# SHTIYA OS: NODE 02 - SECURE REDIS MEMORYSTORE TLS CONFIGURATION
# ==============================================================================

import os
import redis.asyncio as redis
import ssl
import logging

logger = logging.getLogger("ShtiyaOS_Cache")

REDIS_HOST = os.environ.get("REDIS_HOST", "10.0.0.5")  # Private Subnet IP
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6378")) # Memorystore TLS Port
REDIS_AUTH = os.environ.get("REDIS_AUTH")

def create_redis_client() -> redis.Redis:
    """
    Initializes a secure Redis client with strictly enforced TLS encryption.
    """
    try:
        # CA certificate downloaded during provisioning.
        ca_cert_path = os.environ.get("REDIS_CA_CERT", "/etc/redis-tls/ca.pem")

        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_AUTH,
            ssl=True,
            ssl_ca_certs=ca_cert_path,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            decode_responses=True
        )
        return client
    except Exception as e:
        logger.error(f"Failed to initialize Redis TLS Connection: {str(e)}")
        raise

redis_client = create_redis_client()