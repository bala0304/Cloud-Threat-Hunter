import json
import logging

# Set up standard logging for better traceability in CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("===== SECURITY EVENT RECEIVED =====")
    
    # Using logger.info instead of print for structured logs
    logger.info(json.dumps(event))

    try:
        # 1. Defensive Check: Ensure 'detail' exists before processing
        detail = event.get("detail")
        if not detail:
            logger.warning("Event missing 'detail' payload. Dropping.")
            return {'statusCode': 400, 'body': 'Invalid event format'}

        # 2. Safe extraction with defaults
        event_name = detail.get("eventName", "Unknown")
        source_ip = detail.get("sourceIPAddress", "Unknown")
        user_identity = detail.get("userIdentity", {})
        user = user_identity.get("userName") or user_identity.get("principalId") or "Unknown"
        region = detail.get("awsRegion", "Unknown")

        # 3. Log parsed data clearly
        logger.info(f"User: {user} | Action: {event_name} | IP: {source_ip} | Region: {region}")

        # 4. Use a Set for faster, more efficient lookups
        suspicious_actions = {
            "CreateAccessKey",
            "AttachUserPolicy",
            "DeleteTrail",
            "CreateUser",
            "DeactivateMFADevice" # Added a critical one
        }

        if event_name in suspicious_actions:
            # In a real scenario, you'd trigger an SNS/Alert here
            logger.error(f"⚠️ SECURITY ALERT: {event_name} detected by {user}!")

    except KeyError as e:
        logger.error(f"Schema error: Missing expected key {str(e)}")
    except Exception as e:
        # Catching everything else to prevent the Lambda from failing silently
        logger.error(f"Unexpected error: {str(e)}")
        return {'statusCode': 500, 'body': 'Internal processing error'}

    return {
        'statusCode': 200,
        'body': json.dumps('Event successfully audited')
    }
