def remove_keys_from_dict(data, keys_to_remove):
    if not isinstance(data, dict):
        return

    for key in keys_to_remove:
        key_parts = key.split('.')
        current_data = data
        for part in key_parts[:-1]:
            current_data = current_data.get(part, {})
        last_key = key_parts[-1]
        if last_key in current_data:
            del current_data[last_key]

    for key, value in data.items():
        remove_keys_from_dict(value, keys_to_remove)