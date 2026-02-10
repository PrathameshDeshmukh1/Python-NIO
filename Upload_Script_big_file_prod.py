import os
import asyncio
from wsgiref import headers
import aiohttp


import hashlib
import logging
import base64
from typing import Dict, Optional

# Set up logging
logging.basicConfig(
    filename='Upload_Script.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logger.info(f"aiohttp default User-Agent: {aiohttp.http.SERVER_SOFTWARE}")


# Environment variables
#COGNITO_TOKEN_URL = "https://beta-auth.services.pv.tatamotors.io/oauth2/token"
COGNITO_TOKEN_URL = "https://auth.services.pv.tatamotors.io/oauth2/token"

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
#API_BASE_URL = "https://beta-services.api.pv.tatamotors.io/v1/ecosystem-integration"
API_BASE_URL = "https://services.api.pv.tatamotors.io/v1/ecosystem-integration"

ALLOW_PARTIAL_UPLOADS = os.getenv("ALLOW_PARTIAL_UPLOADS", "false").lower() == "true"
API_KEY = os.getenv("API_KEY")
ROOT_FOLDER_PATH = os.getenv("ROOT_FOLDER_PATH")
BATCH_TYPE = os.getenv("BATCH_TYPE", "incremental")

# Validate environment variables
for var in ["API_KEY", "CLIENT_ID", "CLIENT_SECRET", "ROOT_FOLDER_PATH", "BATCH_TYPE"]:
    if not globals()[var]:
        logger.error(f"{var} environment variable is not set")
        raise ValueError(f"{var} environment variable is not set")

async def get_cognito_token() -> str:
    logger.info("Requesting Cognito token...")
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        data = {
            'grant_type': 'client_credentials',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            #'scope': 'uat-ecosystem-integration-ingestion-api/type:plm'
			#Prod
			'scope': 'prod-ecosystem-integration-ingestion-api/type:plm'

        }
        async with session.post(COGNITO_TOKEN_URL, data=data) as response:
            if response.status == 200:
                token_data = await response.json()
                logger.info("Successfully obtained Cognito token.")
                return token_data['access_token']
            else:
                error_text = await response.text()
                logger.error(f"Failed to get token: {response.status}, Error response: {error_text}")
                raise Exception(f"Failed to get token: {response.status}, Error response: {error_text}")

'''
async def create_batch(session: aiohttp.ClientSession, token: str, batch_type: str) -> str:
    logger.info("Creating a new batch...")


	default_ua = aiohttp.http.SERVER_SOFTWARE
    logger.info(f"Default aiohttp User-Agent: {default_ua}")



    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
		'User-Agent': default_ua
    }
    data = {
        "type": batch_type,
        "triggerType": "SCHEDULED",
        "source": "plm"
    }
    
    
    request_url = f"{API_BASE_URL}/batch"
    logger.info(f"Batch POST URL (Host should be derived from this): {request_url}") 
    logger.info(f"Batch creation request payload: {data}")
    logger.info(f"Batch creation headers: {headers}")
	logger.info(f"User-Agent being sent for batch creation: {headers['User-Agent']}")
	
    
    async with session.post(f"{API_BASE_URL}/batch", headers=headers, json=data) as response:
        error_text = await response.text()
    if response.status == 200:
        batch_data = await response.json()
        logger.info(f"Batch created successfully with ID: {batch_data['batchId']}")
        return batch_data['batchId']
    else:
        logger.error(f"Failed to create batch: {response.status}, Response: {error_text}")
        raise Exception(f"Failed to create batch: {response.status}, Response: {error_text}")'''


"""
    async with session.post(f"{API_BASE_URL}/batch", headers=headers, json=data) as response:
        if response.status == 200:
            batch_data = await response.json()
            logger.info(f"Batch created successfully with ID: {batch_data['batchId']}")
            return batch_data['batchId']
        else:
            logger.error(f"Failed to create batch: {response.status}")
            raise Exception(f"Failed to create batch: {response.status}")
    """


async def create_batch(session: aiohttp.ClientSession, token: str, batch_type: str) -> str:
    logger.info("Creating a new batch...")

    # Correct indentation here
    default_ua = aiohttp.http.SERVER_SOFTWARE
    logger.info(f"Default aiohttp User-Agent: {default_ua}")

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'User-Agent': default_ua
    }

    data = {
        "type": batch_type,
        "triggerType": "SCHEDULED",
        "source": "plm"
    }

    request_url = f"{API_BASE_URL}/batch"
    logger.info(f"Batch POST URL (Host should be derived from this): {request_url}") 
    logger.info(f"Batch creation request payload: {data}")
    logger.info(f"Batch creation headers: {headers}")
    logger.info(f"User-Agent being sent for batch creation: {headers['User-Agent']}")

    async with session.post(f"{API_BASE_URL}/batch", headers=headers, json=data) as response:
        error_text = await response.text()

        if response.status == 200:
            batch_data = await response.json()
            logger.info(f"Batch created successfully with ID: {batch_data['batchId']}")
            return batch_data['batchId']
        else:
            logger.error(f"Failed to create batch: {response.status}, Response: {error_text}")
            raise Exception(f"Failed to create batch: {response.status}, Response: {error_text}")



async def calculate_sha256(file_path: str) -> str:
    logger.info(f"Calculating SHA256 for file: {file_path}")
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    sha256_value = sha256_hash.hexdigest()
    logger.info(f"SHA256 for file {file_path}: {sha256_value}")
    return sha256_value

async def get_presigned_url(session: aiohttp.ClientSession, token: str, batch_id: str, file_info: Dict[str, str]) -> Optional[str]:
    logger.info(f"Getting presigned URL for file: {file_info['file_path']}")
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }
    checksum_bytes = bytes.fromhex(file_info['sha256'])
    checksum_base64 = base64.b64encode(checksum_bytes).decode('utf-8')
    data = {
        "category": file_info['category'],
        "fileName": os.path.basename(file_info['file_path']),
        "checksum": checksum_base64
    }
    async with session.post(f"{API_BASE_URL}/batch/{batch_id}/sign_request", headers=headers, json=data) as response:
        if response.status == 200:
            url = await response.text()
            logger.info(f"Successfully got presigned URL for file {file_info['file_path']}")
            return url
        else:
            logger.error(f"Failed to get presigned URL for {file_info['file_path']}: {response.status}")
            return None
'''
async def upload_file(session: aiohttp.ClientSession, file_path: str, presigned_url: str, sha256: str) -> bool:
    logger.info(f"Uploading file: {file_path}")
    headers = {
        "x-amz-sdk-checksum-algorithm": "SHA256",
        "x-amz-checksum-sha256": base64.b64encode(bytes.fromhex(sha256)).decode()
    }
    for attempt in range(3):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
            async with session.put(presigned_url, data=file_content, headers=headers) as response:
                if response.status == 200:
                    logger.info(f"Successfully uploaded {file_path}")
                    return True
                else:
                    error_text = await response.text()
                    logger.warning(f"Upload failed for {file_path}: Status {response.status}, Error: {error_text}. Retrying...")
                    await asyncio.sleep(2 ** attempt)
        except Exception as e:
            logger.error(f"Error uploading {file_path}: {str(e)}. Retrying...")
            await asyncio.sleep(2 ** attempt)
    logger.error(f"Failed to upload {file_path} after 3 attempts")
    return False
'''

async def upload_file(session: aiohttp.ClientSession, file_path: str, presigned_url: str, sha256: str) -> bool:
    logger.info(f"Uploading file: {file_path}")
    headers = {
        "x-amz-sdk-checksum-algorithm": "SHA256",
        "x-amz-checksum-sha256": base64.b64encode(bytes.fromhex(sha256)).decode()
    }
    for attempt in range(3):
        try:
            with open(file_path, 'rb') as file:
                async with session.put(presigned_url, data=file, headers=headers) as response:
                    if response.status == 200:
                        logger.info(f"Successfully uploaded {file_path}")
                        return True
                    else:
                        error_text = await response.text()
                        logger.warning(f"Upload failed for {file_path}: Status {response.status}, Error: {error_text}. Retrying...")
                        await asyncio.sleep(2 ** attempt)
        except Exception as e:
            logger.error(f"Error uploading {file_path}: {str(e)}. Retrying...")
            await asyncio.sleep(2 ** attempt)
    logger.error(f"Failed to upload {file_path} after 3 attempts")
    return False


async def process_files(session: aiohttp.ClientSession, token: str, batch_id: str, root_folder: str):
    logger.info(f"Processing files in folder: {root_folder}")
    file_category_map = {
        "model-variant-input.json": "model_variant",
        #"ecu-did-param-input.json": "ecu_did",
        "ecu-data-input.json": "ecu_data"
    }

    zip_path = os.path.join(root_folder, "ecu-software-release-did-input.zip")
    json_path = os.path.join(root_folder, "ecu-software-release-did-input.json")

    if os.path.isfile(zip_path):
        file_category_map["ecu-software-release-did-input.zip"] = "binary_upload"
    elif os.path.isfile(json_path):
        file_category_map["ecu-software-release-did-input.json"] = "software_release"


    for file_name, category in file_category_map.items():
        file_path = os.path.join(root_folder, file_name)
        if os.path.isfile(file_path):
            logger.info(f"Processing file: {file_name} with category: {category}")
            sha256 = await calculate_sha256(file_path)
            presigned_url = await get_presigned_url(session, token, batch_id, {
                'file_path': file_path,
                'sha256': sha256,
                'category': category
            })
            if presigned_url:
                success = await upload_file(session, file_path, presigned_url, sha256)
                if not success and not ALLOW_PARTIAL_UPLOADS:
                    await abort_batch(session, token, batch_id)
                    return False
    return True

"""
async def complete_batch(session: aiohttp.ClientSession, token: str, batch_id: str):
    logger.info(f"Completing batch: {batch_id}")
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }
    async with session.post(f"{API_BASE_URL}/batch/{batch_id}/complete", headers=headers) as response:
        if response.status == 200:
            logger.info(f"Batch {batch_id} completed successfully")
        else:
            logger.error(f"Failed to complete batch {batch_id}: {response.status}") """

async def complete_batch(session: aiohttp.ClientSession, token: str, batch_id: str, retries: int = 3):
    logger.info(f"Completing batch: {batch_id}")
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }

    for attempt in range(1, retries + 1):
        try:
            async with session.post(f"{API_BASE_URL}/batch/{batch_id}/complete", headers=headers) as response:
                if response.status == 200:
                    logger.info(f"Batch {batch_id} completed successfully")
                    return  # success, exit the function
                else:
                    error_text = await response.text()
                    logger.error(f"Attempt {attempt}: Failed to complete batch {batch_id} - Status: {response.status}, Response: {error_text}")

                    if response.status == 500 and attempt < retries:
                        wait_time = 2 ** attempt
                        logger.info(f"Server error encountered. Retrying after {wait_time} seconds...")
                        await asyncio.sleep(wait_time)
                    else:
                        break  # non-retryable error or no retries left
        except Exception as e:
            logger.error(f"Attempt {attempt}: Exception while completing batch {batch_id}: {str(e)}")
            if attempt < retries:
                wait_time = 2 ** attempt
                logger.info(f"Retrying after exception in {wait_time} seconds...")
                await asyncio.sleep(wait_time)
            else:
                break

    logger.error(f"Failed to complete batch {batch_id} after {retries} attempts")

async def abort_batch(session: aiohttp.ClientSession, token: str, batch_id: str):
    logger.info(f"Aborting batch: {batch_id}")
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }
    data = {
        "abortReason": "File upload failures"
    }
    async with session.post(f"{API_BASE_URL}/batch/{batch_id}/abort", headers=headers, json=data) as response:
        if response.status == 200:
            logger.info(f"Batch {batch_id} aborted")
        else:
            logger.error(f"Failed to abort batch {batch_id}: {response.status}")

async def main():
    try:
        logger.info("Starting the process...")
        if not os.path.isdir(ROOT_FOLDER_PATH):
            raise ValueError(f"The specified path '{ROOT_FOLDER_PATH}' is not a valid directory.")
        token = await get_cognito_token()
        from aiohttp import ClientSession, TCPConnector
        connector = TCPConnector(ssl=False)
        async with ClientSession(connector=connector) as session:
            batch_id = await create_batch(session, token, BATCH_TYPE)
            success = await process_files(session, token, batch_id, ROOT_FOLDER_PATH)
            if success:
                await complete_batch(session, token, batch_id)
            else:
                await abort_batch(session, token, batch_id)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())


