
def generate_unauthorized_message_components(logger, config, response_class, meta_class, error_class, _id, status_code):
    logger.info(f"[{_id}] create unathorized response data")
    _response_message = config.messages.unauthorized
    _response = response_class
    _meta = meta_class(_id=_id, successful=False, message=_response_message)
    _data = None
    _error = error_class(error_message=_response_message)
    _status_code = status_code

    return _response_message, _response, _meta, _data, _error, _status_code

