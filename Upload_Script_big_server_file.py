import os
import asyncio
from wsgiref import headers
import aiohttp


import hashlib
import logging
import base64
from typing import Dict, Optional

'''
def get_vcid_logger(vcid: str, log_folder: str, central_log_path: str = "/user/uaprodtrl/ECU_Code/NIO/Upload_Script.log") -> logging.Logger:
    """Create a logger that writes to VCIDnumber.log"""
    os.makedirs(log_folder, exist_ok=True)
    os.makedirs(os.path.dirname(central_log_path), exist_ok=True)
    logger = logging.getLogger(vcid)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # prevent duplicate logs

    # Prevent adding multiple handlers if logger already exists
    if not logger.handlers:
        vcid_log_file = os.path.join(vcid_folder_path, f"{vcid}.log")
        vcid_handler = logging.FileHandler(vcid_log_file)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        vcid_handler.setFormatter(formatter)
        logger.addHandler(vcid_handler)

        central_handler = logging.FileHandler(central_log_path)
        central_handler.setFormatter(formatter)
        logger.addHandler(central_handler)

    return logger '''

def get_vcid_logger(vcid: str, vcid_folder_path: str, central_log_path: str = "/user/uaprodtrl/ECU_Code/NIO/Upload_Script.log") -> logging.Logger:
    """
    Create a logger that writes to both:
     VCID _NIO folder
     Central log
    """
    # Make sure folders exist
    os.makedirs(vcid_folder_path, exist_ok=True)
    os.makedirs(os.path.dirname(central_log_path), exist_ok=True)

    logger = logging.getLogger(vcid)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Avoid double logging to root

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        # VCID _NIO folder log
        vcid_log_file = os.path.join(vcid_folder_path, f"{vcid}.log")
        vcid_handler = logging.FileHandler(vcid_log_file)
        vcid_handler.setFormatter(formatter)
        logger.addHandler(vcid_handler)

        # Central log file
        central_handler = logging.FileHandler(central_log_path)
        central_handler.setFormatter(formatter)
        logger.addHandler(central_handler)

    return logger



# Set up logging
logging.basicConfig(
    filename='Upload_Script.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

logger.info(f"aiohttp default User-Agent: {aiohttp.http.SERVER_SOFTWARE}")


# Environment variables
COGNITO_TOKEN_URL = "https://beta-auth.services.pv.tatamotors.io/oauth2/token"
#COGNITO_TOKEN_URL = "https://auth.services.pv.tatamotors.io/oauth2/token"

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
API_BASE_URL = "https://beta-services.api.pv.tatamotors.io/v1/ecosystem-integration"
#API_BASE_URL = "https://services.api.pv.tatamotors.io/v1/ecosystem-integration"

ALLOW_PARTIAL_UPLOADS = os.getenv("ALLOW_PARTIAL_UPLOADS", "false").lower() == "true"
API_KEY = os.getenv("API_KEY")
#ROOT_FOLDER_PATH = os.getenv("ROOT_FOLDER_PATH")
ROOT_FOLDER_PATH = "/tmp"
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
            'scope': 'uat-ecosystem-integration-ingestion-api/type:plm'
			#Prod
			#'scope': 'prod-ecosystem-integration-ingestion-api/type:plm'

        }
        async with session.post(COGNITO_TOKEN_URL, data=data) as response:
            if response.status in (200,201):
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


async def create_batch(session: aiohttp.ClientSession, token: str, batch_type: str, logger: logging.Logger) -> str:
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

        if response.status in (200,201):
            batch_data = await response.json()
            logger.info(f"Batch created successfully with ID: {batch_data['batchId']}")
            return batch_data['batchId']
        else:
            logger.error(f"Failed to create batch: {response.status}, Response: {error_text}")
            raise Exception(f"Failed to create batch: {response.status}, Response: {error_text}")



async def calculate_sha256(file_path: str, logger: logging.Logger) -> str:
    logger.info(f"Calculating SHA256 for file: {file_path}")
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    sha256_value = sha256_hash.hexdigest()
    logger.info(f"SHA256 for file {file_path}: {sha256_value}")
    return sha256_value

async def get_presigned_url(session: aiohttp.ClientSession, token: str, batch_id: str, file_info: Dict[str, str], logger: logging.Logger) -> Optional[str]:
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
        if response.status in (200,201):
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

async def upload_file(session: aiohttp.ClientSession, file_path: str, presigned_url: str, sha256: str, logger: logging.Logger) -> bool:
    logger.info(f"Uploading file: {file_path}")
    headers = {
        "x-amz-sdk-checksum-algorithm": "SHA256",
        "x-amz-checksum-sha256": base64.b64encode(bytes.fromhex(sha256)).decode()
    }
    for attempt in range(3):
        try:
            with open(file_path, 'rb') as file:
                async with session.put(presigned_url, data=file, headers=headers) as response:
                    if response.status in (200,201):
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
def resolve_input_folder(tmp_root: str, logger: logging.Logger) -> str:
    logger.info(f"Resolving input folder inside: {tmp_root}")

    # Find *_NIO folder
    nio_folders = [
        d for d in os.listdir(tmp_root)
        if d.endswith("_NIO") and os.path.isdir(os.path.join(tmp_root, d))
    ]

    if not nio_folders:
        logger.error("No *_NIO folder found inside /tmp")
        raise FileNotFoundError("No *_NIO folder found inside /tmp")

    nio_folder = os.path.join(tmp_root, nio_folders[0])
    logger.info(f"Found NIO folder: {nio_folder}")

    # Find VCID folder inside *_NIO
    vcid_folders = [
        d for d in os.listdir(nio_folder)
        if os.path.isdir(os.path.join(nio_folder, d))
    ]

    if not vcid_folders:
        logger.error(f"No VCID folder found inside {nio_folder}")
        raise FileNotFoundError(f"No VCID folder found inside {nio_folder}")

    vcid_folder = os.path.join(nio_folder, vcid_folders[0])
    logger.info(f"Resolved VCID folder: {vcid_folder}")

    return vcid_folder
'''

def get_nio_and_vcid_folders(tmp_root: str, logger: logging.Logger):
    """
    Return a list of tuples: [(nio_folder_path, vcid_folder_path), ...]
    """
    logger.info(f"Scanning {tmp_root} for *_NIO folders...")
    nio_folders = [
        os.path.join(tmp_root, d)
        for d in os.listdir(tmp_root)
        if d.endswith("_NIO") and os.path.isdir(os.path.join(tmp_root, d))
    ]

    if not nio_folders:
        logger.error("No *_NIO folders found in /tmp")
        raise FileNotFoundError("No *_NIO folders found in /tmp")

    nio_vcid_pairs = []
    for nio_folder in nio_folders:
        vcid_folders = [
            os.path.join(nio_folder, d)
            for d in os.listdir(nio_folder)
            if os.path.isdir(os.path.join(nio_folder, d))
        ]
        if not vcid_folders:
            logger.warning(f"No VCID folders found inside {nio_folder}")
            continue
        for vcid_folder in vcid_folders:
            nio_vcid_pairs.append((nio_folder, vcid_folder))

    return nio_vcid_pairs







async def process_files(session: aiohttp.ClientSession, token: str, batch_id: str, root_folder: str, logger: logging.Logger):
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
            sha256 = await calculate_sha256(file_path, logger)
            presigned_url = await get_presigned_url(session, token, batch_id, {
                'file_path': file_path,
                'sha256': sha256,
                'category': category
            }, logger)
            if presigned_url:
                success = await upload_file(session, file_path, presigned_url, sha256, logger)
                if not success and not ALLOW_PARTIAL_UPLOADS:
                    await abort_batch(session, token, batch_id, logger)
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

async def complete_batch(session: aiohttp.ClientSession, token: str, batch_id: str, logger: logging.Logger, retries: int = 3):
    logger.info(f"Completing batch: {batch_id}")
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }

    for attempt in range(1, retries + 1):
        try:
            async with session.post(f"{API_BASE_URL}/batch/{batch_id}/complete", headers=headers) as response:
                if response.status in (200,201):
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

async def abort_batch(session: aiohttp.ClientSession, token: str, batch_id: str, logger: logging.Logger):
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
        if response.status in (200,201):
            logger.info(f"Batch {batch_id} aborted")
        else:
            logger.error(f"Failed to abort batch {batch_id}: {response.status}")

'''
async def main():
    try:
        logger.info("Starting the process...")
        if not os.path.isdir(ROOT_FOLDER_PATH):
            raise ValueError(f"The specified path '{ROOT_FOLDER_PATH}' is not a valid directory.")

        token = await get_cognito_token()

        from aiohttp import ClientSession, TCPConnector
        connector = TCPConnector(ssl=False)

        async with ClientSession(connector=connector) as session:
            input_folder = resolve_input_folder(ROOT_FOLDER_PATH, logger)
            #vcid = os.path.basename(input_folder)
            #logger_vcid = get_vcid_logger(vcid)
            #logger_vcid.info("Starting the process for VCID: %s", vcid)
            #logger_vcid.info("Resolved VCID folder: %s", input_folder)
            #input_folder = resolve_input_folder(ROOT_FOLDER_PATH, logger)
            vcid = os.path.basename(input_folder)

            # Get the parent NIO folder of this VCID folder
            vcid_nio_folder = os.path.dirname(input_folder)

            # Pass the VCID NIO folder path to logger
            logger_vcid = get_vcid_logger(vcid, vcid_folder_path=vcid_nio_folder,central_log_path="/user/uaprodtrl/ECU_Code/NIO/Upload_Script.log")
            logger_vcid.info("Starting the process for VCID: %s", vcid)
            logger_vcid.info("Resolved VCID folder: %s", input_folder)

            batch_id = await create_batch(session, token, BATCH_TYPE, logger_vcid)

    # Corrected: pass only 1 logger
            success = await process_files(session, token, batch_id, input_folder, logger_vcid)

            if success:
                 await complete_batch(session, token, batch_id, logger=logger_vcid)
            else:
                 await abort_batch(session, token, batch_id, logger=logger_vcid)
 

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
'''

def read_pv_ev_category(nio_folder: str, logger: logging.Logger) -> str:
    """
    Reads Category_PV_EV.txt from the given _NIO folder.
    Expected content: EV or PV
    """
    category_file = os.path.join(nio_folder, "Category_PV_EV.txt")

    if not os.path.isfile(category_file):
        logger.error(f"Category_PV_EV.txt not found in {nio_folder}")
        raise FileNotFoundError(f"Category_PV_EV.txt not found in {nio_folder}")

    with open(category_file, "r") as f:
        value = f.read().strip().upper()

    if value not in ("EV", "PV"):
        logger.error(f"Invalid value in Category_PV_EV.txt: '{value}' (expected EV or PV)")
        raise ValueError(f"Invalid Category_PV_EV.txt value: {value}")

    logger.info(f"Detected vehicle category: {value} for NIO folder: {nio_folder}")
    return value



async def main():
    try:
        logger.info("Starting the process...")
        if not os.path.isdir(ROOT_FOLDER_PATH):
            raise ValueError(f"The specified path '{ROOT_FOLDER_PATH}' is not a valid directory.")

        token = await get_cognito_token()

        from aiohttp import ClientSession, TCPConnector
        connector = TCPConnector(ssl=False)

        async with ClientSession(connector=connector) as session:
            # Get all _NIO folders and VCID subfolders
            nio_vcid_pairs = get_nio_and_vcid_folders(ROOT_FOLDER_PATH, logger)

            if not nio_vcid_pairs:
                logger.error("No _NIO folders with VCID subfolders found.")
                return

            for nio_folder, vcid_folder in nio_vcid_pairs:
                try:
                    vcid = os.path.basename(vcid_folder)

                    logger_vcid = get_vcid_logger(
                        vcid,
                        vcid_folder_path=nio_folder,
                        central_log_path="/user/uaprodtrl/ECU_Code/NIO/Upload_Script.log"
                    )

                    logger_vcid.info(f"Starting transfer for VCID: {vcid}")
                    logger_vcid.info(f"Resolved VCID folder: {vcid_folder}")

                    # Proceed with batch creation and file upload
                    batch_id = await create_batch(session, token, BATCH_TYPE, logger_vcid)
                    success = await process_files(session, token, batch_id, vcid_folder, logger_vcid)

                    if success:
                        await complete_batch(session, token, batch_id, logger_vcid)
                    else:
                        await abort_batch(session, token, batch_id, logger_vcid)

                except Exception as e:
                    logger.error(f"An error occurred while processing VCID {vcid}: {str(e)}")

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())



       


