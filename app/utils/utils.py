
def generate_unauthorized_message_components(logger, config, response_class, meta_class, error_class, _id, status_code):
    logger.info(f"[{_id}] create unathorized response data")
    _response_message = config.messages.unauthorized
    _response = response_class
    _meta = meta_class(_id=_id, successful=False, message=_response_message)
    _data = None
    _error = error_class(error_message=_response_message)
    _status_code = status_code

    return _response_message, _response, _meta, _data, _error, _status_code


def get_orjson_response(logger, _id, _response, _meta, _data, _error, _status_code, orjson_response_class):
    # create response
    logger.info(f"[{_id}] create response")
    _content = _response(meta=_meta, data=_data, error=_error)
    return orjson_response_class(status_code=_status_code, content=_content.model_dump())
    
 
