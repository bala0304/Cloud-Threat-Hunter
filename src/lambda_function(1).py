import json
import logging
import urllib3
import re

# Set up standard logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 1. Global Initialization (Reuse connections for performance)
http = urllib3.PoolManager()
IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

def get_ip_intel(ip_address):
    """Fetches Geolocation and ISP data from ip-api.com"""
    # Defensive check: if IP is 'Unknown' or invalid, don't call the API
    if not ip_address or ip_address == "Unknown" or not IP_PATTERN.match(str(ip_address)):
        return {"status": "skipped", "message": "Invalid or Internal IP"}
    
    # URL for ip-api.com (Free Tier)
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,org,as"
    
    try:
        # 2.0 second timeout to ensure the Lambda doesn't hang
        response = http.request('GET', url, timeout=2.0)
        if response.status == 200:
            return json.loads(response.data.decode('utf-8'))
    except Exception as e:
        logger.error(f"OSINT Lookup Failed: {e}")
    
    return {"status": "error", "message": "Lookup timed out or failed"}

def lambda_handler(event, context):
    logger.info("===== SECURITY EVENT RECEIVED =====")
    logger.info(json.dumps(event))

    try:
        detail = event.get("detail")
        if not detail:
            logger.warning("Event missing 'detail' payload. Dropping.")
            return {'statusCode': 400, 'body': 'Invalid event format'}

        # extraction
        event_name = detail.get("eventName", "Unknown")
        source_ip = detail.get("sourceIPAddress", "Unknown")
        user_identity = detail.get("userIdentity", {})
        user = user_identity.get("userName") or user_identity.get("principalId") or "Unknown"
        region = detail.get("awsRegion", "Unknown")

        # --- NEW ENRICHMENT STEP ---
        # We perform the OSINT lookup immediately after finding the IP
        ip_intel = get_ip_intel(source_ip)
        country = ip_intel.get("country", "Unknown")
        isp = ip_intel.get("isp", "Unknown")
        
        # Log parsed data WITH the new OSINT details
        logger.info(f"User: {user} | Action: {event_name} | IP: {source_ip} ({country} - {isp}) | Region: {region}")

        suspicious_actions = {
            "CreateAccessKey",
            "AttachUserPolicy",
            "DeleteTrail",
            "CreateUser",
            "DeactivateMFADevice"
        }

        if event_name in suspicious_actions:
            # Enhanced Alert with Intel
            logger.error(f"⚠️ SECURITY ALERT: {event_name} detected by {user}!")
            logger.error(f"🔍 THREAT INTEL: IP {source_ip} is hosted by '{isp}' in {country}.")
            
            # If you want to see the full JSON raw data in logs:
            logger.info(f"Full Intel Data: {json.dumps(ip_intel)}")

    except KeyError as e:
        logger.error(f"Schema error: Missing expected key {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {'statusCode': 500, 'body': 'Internal processing error'}

    return {
        'statusCode': 200,
        'body': json.dumps('Event successfully audited and enriched')
    }
