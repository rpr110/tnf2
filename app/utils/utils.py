import secrets
import string 

import smtplib
import ssl
from email.message import EmailMessage

email_sender = 'ryangrid110@gmail.com'
email_password = 'oibtnyimklezstao'

def remove_keys_from_dict(data:dict, keys_to_remove:list)->None:
    
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

def create_verification_code(code_length:int):
    characters = string.ascii_letters + string.digits
    verification_code = "".join(secrets.choice(characters) for _ in range(code_length))
    return verification_code


def send_mail(email_receiver:str, subject:str, body:str):
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())

