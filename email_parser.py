import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

def parse_eml_file(file):
    try:
        msg = BytesParser(policy=policy.default).parse(file)

        headers = dict(msg.items())
        headers['Return-Path'] = msg.get('Return-Path', '')
        headers['Reply-To'] = msg.get('Reply-To', '')

        body = ''
        html_content = ''

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    html_content = part.get_content()
                elif content_type == "text/plain" and not html_content:
                    body = part.get_content()
        else:
            content_type = msg.get_content_type()
            if content_type == "text/html":
                html_content = msg.get_content()
            elif content_type == "text/plain":
                body = msg.get_content()

        used_body = html_content if html_content else body

        # Extract URLs using BeautifulSoup for better accuracy
        soup = BeautifulSoup(used_body, 'html.parser')
        urls = [link['href'] for link in soup.find_all('a', href=True)]

        return {
            'subject': msg['subject'],
            'from': msg['from'],
            'to': msg['to'],
            'Headers': headers,
            'Body': used_body,
            'URLs': urls
        }
    except Exception as e:
        return {
            'error': str(e),
            'subject': '',
            'from': '',
            'to': '',
            'Headers': {},
            'Body': '',
            'URLs': []
        }