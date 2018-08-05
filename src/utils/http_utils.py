import logging
import requests
import traceback

import logging

logger = logging.getLogger(__name__)

enable_trace = True


def http_post_request(url, headers=None, body=None, auth=None):
    headers = headers or {}
    body = body or ""
    try:
        logging.debug("POST URL------> " + url)
        logging.debug("POST Headers------> " + str(headers))
        #logging.debug("POST Data------> " + body)
        result = requests.post(url, headers=headers, json=body, auth=auth, verify=False)
        logging.debug("Status code --> " + str(result.status_code))
        #logging.debug("Result Body --> " + result.text)
        return result
    except Exception as e:
        logging.error(
            "Exception when requesting POST {url},  with headers: {headers}, and body: {body}, AND ERROR: {error}, TRACE: {stack_trace}".format(
                error=str(e), url=url, headers=headers, body=body,
                stack_trace=traceback.format_exc()) if enable_trace else "")


def http_get_request(url, headers=None, auth=None):
    headers = headers or {}
    try:
        logging.debug("GET URL------> " + url)
        logging.debug("GET Headers------> " + str(headers))
        result = requests.get(url, headers=headers, auth=auth, verify=False)
        logging.debug("Status code --> " + str(result.status_code))
        #logging.debug("Body ---------> " + str(result.text))
        return str(result.text)
    except Exception as e:
        logging.error(
            "Exception when requesting GET {url},  with headers: {headers}, AND ERROR: {error}, TRACE: {stack_trace}".format(
                error=str(e), url=url, headers=headers, stack_trace=traceback.format_exc() if enable_trace else ""))


def http_delete_request(url, headers=None, auth=None):
    try:
        headers = headers or {}
        logging.debug("DELETE URL------> " + url)
        logging.debug("DELETE Headers------> " + str(headers))
        result = requests.delete(url, headers=headers, auth=auth, verify=False)
        logging.debug("Status code --> " + str(result.status_code))
        #logging.debug("Body ---------> " + result.text.encode('utf-8').strip())

    except Exception as e:
        logging.error(
            "Exception when requesting DELETE {url},  with headers: {headers}, AND ERROR: {error}, TRACE: {stack_trace}".format(
                error=str(e), url=url, headers=headers, stack_trace=traceback.format_exc() if enable_trace else ""))
        raise
