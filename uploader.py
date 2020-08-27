import argparse
import logging
import uuid
import os
import zipfile
import tempfile
import typing 
import sys
import requests
import itertools
import gc

from pathlib import Path

VERSION = "1.0.0-alpha"

class LoggedObject:
    def _truncate_class_name(self, class_name: str, max_length: int):
        return class_name[:max_length-2] + ".." if len(class_name) > max_length else class_name
        
    def _format_log_message(self, msg: str, *args):
        return "{: <12}: {}".format(self._truncate_class_name(type(self).__name__, 12), msg.format(*args))
    
    def _log(self, level, msg: str, *args):
        self._logger.log(level, self._format_log_message(msg, *args))
        
    def __init__(self, logger: logging.Logger):
        self._logger = logger

        
class RotatableTemporaryZipFileAppender(LoggedObject):
    # todo: asyncio
    
    def _should_rotate(self) -> bool:
        return self._iteration_total_bytes >= self._rotate_at_bytes
    
    def _get_temp_path(self) -> str:
        assert self._session, "Ensure to open resources with `with .. as ..`"
        
        temp_path = "{}/ca-uploads/{}".format(tempfile.gettempdir(), self._session)
        self._log(logging.INFO, "Using temporary path: {}/".format(temp_path))
        
        return temp_path
        
    def _ensure_path(self, path: str):
        Path(path).mkdir(parents=True, exist_ok=True)
        
    def _close_current_handle(self) -> None:
        self._log(logging.INFO, "Closing: {}", self._tmp_paths[-1])
        self._handle.close()
        gc.collect()
        
    def _rotate_handle(self):
        if self._handle:
            self._log(logging.DEBUG, "Closing handle #{} at {} bytes at path: {}", self._iteration - 1, 
                        self._iteration_total_bytes, self._tmp_paths[-1])
            self._close_current_handle()

        tmp_path = self._get_temp_path()
        file_path = "{}/{}.{}.zip".format(tmp_path, self._file_name, self._iteration)

        self._ensure_path(tmp_path)
        self._tmp_paths.append(file_path)

        self._log(logging.DEBUG, "Creating new handle #{} at path: {}", self._iteration, file_path)
        self._handle = zipfile.ZipFile(file_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True)

        self._iteration += 1
        self._iteration_total_bytes = 0
        
    def _get_handle(self):
        if not self._handle or self._should_rotate():
            self._rotate_handle()
        return self._handle
        
    @property
    def zip_files(self):
        return self._tmp_paths
    
    def __init__(self, logger: logging.Logger, file_name: str, rotate_at_bytes: int = 5e8):
        super().__init__(logger)
        
        self._log(logging.DEBUG, "Rotateable zip file for name '{}' rotates at bytes: {}", file_name, rotate_at_bytes)
        self._file_name = file_name
        self._rotate_at_bytes = rotate_at_bytes
        self._tmp_paths = []
        
        self._iteration = 1
        self._iteration_total_bytes = 0
        
        self._handle = None
        self._session = None
        
    def add(self, entry: os.DirEntry, local_zip_path: typing.Optional[str] = None) -> None:
        stats = entry.stat(follow_symlinks=False)
        handle = self._get_handle()
        
        self._iteration_total_bytes += stats.st_size
        handle.write(entry.path, local_zip_path if local_zip_path else None)
        
    def __enter__(self):
        self._session = str(uuid.uuid4())
        self._log(logging.INFO, "Session: {}", self._session)
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        assert self._iteration > 1 or self._iteration_total_bytes > 0, "Empty zip file. No files were added."
        self._close_current_handle()
        self._handle = None
        
        
class DirectoryZipUtil(LoggedObject):
    def _scantree(self, path):
        for entry in os.scandir(path):
            if entry.is_dir(follow_symlinks=False):
                yield from self._scantree(entry.path)
            else:
                yield entry

    def __init__(self, logger: logging.Logger, supported_extensions: typing.List[str]):
        super().__init__(logger)
        self._supported_extensions = supported_extensions
        
    def zip_path(self, path: str, suffix: typing.Optional[str] = None, file_name: typing.Optional[str] = "dataset") -> typing.List[str]:
        zip_files = []
        
        with RotatableTemporaryZipFileAppender(self._logger, "{}.{}".format(file_name, suffix) if suffix else file_name) as zip_appender:
            for entry in self._scantree(path):
                if entry.name.startswith('.') or not entry.is_file():
                    self._log(logging.DEBUG, "Unsupported object: {}", entry.name)
                    continue
                    
                if Path(entry.name).suffix not in self._supported_extensions:
                    self._log(logging.WARNING, "Unsupported file: {}", entry.path)
                    continue
                    
                self._log(logging.DEBUG, "Adding zip entry: {}", entry.name)
                zip_appender.add(entry, entry.path.replace(path + '/' if not path.endswith('/') else path, '').strip())
                
            zip_files = zip_appender.zip_files
            
        self._log(logging.DEBUG, "Done zipping files: {}", zip_files)
        return zip_files
    
    
class Api(LoggedObject):
    # todo: add retry logic
    # todo: asyncio
    
    BACKOFFICE_ENDPOINT = "https://tbirqtdxv6.execute-api.eu-central-1.amazonaws.com/dataset/upload/v1"
    
    def _reduct_request_params(self, params: dict) -> dict:
        reducted_params = params.copy()

        if 'token' in params:
            del reducted_params['token']
            
        return reducted_params
    
    def _request(self, endpoint: str, **kwargs) -> dict:
        self._log(logging.INFO, "Requesting '{}': {}", endpoint, self._reduct_request_params(kwargs))
        response = requests.put(Api.BACKOFFICE_ENDPOINT + endpoint, params=kwargs)
        
        assert response.status_code == 200, "Got error from API (session={}): Bad status code {}".format(self._session, response.status_code)
        
        json_response = response.json()
        assert json_response["status"] == "OK", "Got error from API (session={}): {}".format(self._session, json_response['message'])
        
        self._log(logging.DEBUG, "Response '{}': {}", endpoint, json_response)
        return json_response
        
        
    def __init__(self, logger: logging.Logger, customer_id: int, token: str):
        super().__init__(logger)
        
        self._session = None
        self._customer_id = customer_id
        self._token = token
        
        self._log(logging.INFO, "API Endpoint: {}", self.BACKOFFICE_ENDPOINT)
    
    def __enter__(self):
        self._session = str(uuid.uuid4())
        self._log(logging.INFO, "Session: {}", self._session)
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self._session = None
        
    def check_update(self) -> dict:
        return self._request("/check_update", **{
            'version': VERSION,
            'session': self._session,
            'customer': self._customer_id,
            'token': self._token
        })
    
    def generate_presigned_url(self, dataset_name: str, filename: str) -> dict:
        return self._request("/generate", **{
            'dataset': dataset_name,
            'filename': filename,
            'version': VERSION,
            'session': self._session,
            'customer': self._customer_id,
            'token': self._token
        })
    
    def report_upload_error(self, dataset_name: str, error: str) -> dict:
        return self._request("/error", **{
            'dataset': dataset_name,
            'version': VERSION,
            'session': self._session,
            'customer': self._customer_id,
            'token': self._token,
            'error': error
        })
    
    def report_upload_done(self, dataset_name: str) -> dict:
        return self._request("/done", **{
            'dataset': dataset_name,
            'version': VERSION,
            'session': self._session,
            'customer': self._customer_id,
            'token': self._token
        })
    
    
class Uploader(LoggedObject):
    # todo: add retry logic
    # todo: asyncio
    
    def upload_file(self, file_path: str, presigned_url_metadata: dict) -> None:
        presign_url = presigned_url_metadata['presigned']['url']
        presign_fields = presigned_url_metadata['presigned']['fields']
        
        self._log(logging.INFO, "Uploading file {} ...", file_path)
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            response = requests.post(presign_url, data=presign_fields, files=files)
        
        gc.collect()
        
        assert response.status_code == 204, "Upload failed with status: {}".format(response.status_code)
    
    
class Controller(LoggedObject):
    SUPPORTED_EXTENSIONS = [".png", ".jpeg", ".jpg", ".json"]
    
    def _print_warning_messages(self, messages: list) -> None:
        max_message_length = max(map(len, messages))
        
        self._log(logging.WARN, "*" * (max_message_length + 4))
        for message in messages:
            self._log(logging.WARN, f"* {{: <{max_message_length}}} *".format(message.strip()))
        self._log(logging.WARN, "*" * (max_message_length + 4))
    
    def __init__(self, logger: logging.Logger, customer_id: int, token: str):
        super().__init__(logger)
        
        self._customer_id = customer_id
        self._token = token
        
        self._api = Api(self._logger, self._customer_id, self._token)
        self._uploader = Uploader(self._logger)
        self._zip_util = DirectoryZipUtil(self._logger, Controller.SUPPORTED_EXTENSIONS)
        
    def print_update_messages(self) -> None:
        self._log(logging.INFO, "Checking for updates..")
        
        with self._api:
            update_info = self._api.check_update()
            
            if update_info["update_avaliable"]:
                self._print_warning_messages([
                    "A newer version of this client is available.",
                    "Please consider upgrading ASAP.",
                    "Consult your account manager for more information."
                ])
                
            if update_info["message"]:
                self._print_warning_messages(update_info["message"].split("\n"))
                
            if update_info["force_upgrade"]:
                raise Exception("A force upgrade has been issued for your version {}. Please upgrade the utility to continue using it.".format(VERSION))
        
    def zip_and_upload(self, dataset_name: str, path: str, json_path: typing.Optional[str] = None) -> typing.Tuple[int, int]:
        paths = list(filter(lambda x: x, (path, json_path)))
        self._log(logging.INFO, "Zipping paths: {}", paths)
        
        zip_files = list(itertools.chain(*[self._zip_util.zip_path(path, "json" if path is json_path else None) for path in paths]))
        presigned_urls = []
        errors = []
        
        with self._api:
            for zip_file in zip_files:
                presigned_urls.append(self._api.generate_presigned_url(dataset_name, Path(zip_file).stem))
            
            try:
                for file_path, presigned_url in zip(zip_files, presigned_urls):
                    try:
                        self._uploader.upload_file(file_path, presigned_url)
                    except Exception as e:
                        error = "An exception of type {0} occurred ({1}) Arguments: {2!r}" \
                                    .format(type(e).__name__, str(e), e.args)
                        self._api.report_upload_error(dataset_name, error)
                        errors.append(error)
            finally:
                self._api.report_upload_done(dataset_name)
            
        self._log(logging.INFO, "Uploaded {}/{} successfully", len(zip_files) - len(errors), len(zip_files))
        
        if errors:
            self._log(logging.ERROR, "The process has encounterd {} error(s):", len(errors))
            for i, error in enumerate(errors):
                self._log(logging.ERROR, "Error #{}: {}", i, error)
                
        return len(zip_files), len(errors)


def create_logger(debug: typing.Optional[bool] = False):
    logger: logging.Logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logging_handler = logging.StreamHandler(sys.stdout)
    logging_handler.setFormatter(logging.Formatter('%(asctime)-24s [%(levelname)-7s]  %(message)s'))
    logger.handlers = [logging_handler]
    
    return logger


def run_process(logger: logging.Logger, customer_id: int, token: str, dataset_name: str, 
        dataset_path: str, jsons_path: typing.Optional[str] = None):
    
    controller: Controller = Controller(logger, customer_id, token)
    controller.print_update_messages()
    controller.zip_and_upload(dataset_name, dataset_path, jsons_path)
    
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True, prog="ca_uploader", description="CrowdAnnotations dataset uploader")
    
    parser.add_argument('-c', '--customer', help='Your customer id', required=True, type=int)
    parser.add_argument('-t', '--token', help='Your customer secret token', required=True, type=str)
    parser.add_argument('-n', '--dataset-name', help='Name of dataset', required=True, type=str)
    parser.add_argument('-p', '--dataset-path', help='Local path to dataset', required=True, type=str)
    parser.add_argument('-b', '--bbox-path', help='Local path to bbox .json files, if applicable to the dataset', required=False, type=str)
    parser.add_argument('-v', '--verbose', help='For debugging', action="store_true", default=False)
    
    args = parser.parse_args()
    logger = create_logger(args.verbose)
    
    try:
        run_process(logger, args.customer, args.token, args.dataset_name, 
                    args.dataset_path[:-1] if args.dataset_path.endswith('/') else args.dataset_path, 
                    args.bbox_path[:-1] if args.bbox_path and args.bbox_path.endswith('/') else args.bbox_path)
    except Exception as e:
        logger.error("Process ended with an error: {}".format(e))