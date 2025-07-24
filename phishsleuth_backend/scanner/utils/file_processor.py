# scanner/utils/file_processor.py
import email
import re
import magic
import logging
from typing import Dict, Any
from email import policy
from email.parser import BytesParser
from pathlib import Path

try:
    import extract_msg  # type: ignore
except ImportError:
    extract_msg = None

logger = logging.getLogger(__name__)

class FileProcessor:
    """Handle different file types for email analysis"""
    
    SUPPORTED_FORMATS = {
        'text/plain': '.txt',
        'message/rfc822': '.eml',
        'application/vnd.ms-outlook': '.msg',
        'text/html': '.html'
    }
    
    def __init__(self):
        self.magic = magic.Magic(mime=True)
    
    def process_file(self, file_path: str) -> Dict[str, Any]:
        """Process uploaded file and extract email content"""
        try:
            file_type = self.magic.from_file(file_path)
            logger.info(f"Processing file: {file_path}, Type: {file_type}")
            
            if file_type == 'message/rfc822':
                return self._process_eml_file(file_path)
            elif file_type == 'application/vnd.ms-outlook':
                return self._process_msg_file(file_path)
            elif file_type in ['text/plain', 'text/html']:
                return self._process_text_file(file_path)
            else:
                raise ValueError(f"Unsupported file type: {file_type}")
                
        except Exception as e:
            logger.error(f"File processing failed: {e}")
            return {
                'error': str(e),
                'subject': '',
                'body': '',
                'headers': {},
                'attachments': []
            }

    def _process_eml_file(self, file_path: str) -> Dict[str, Any]:
        """Parse .eml file"""
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        subject = msg['subject'] or ''
        headers = {k: v for k, v in msg.items()}
        body = self._get_email_body(msg)
        attachments = self._get_attachments(msg)

        return {
            'subject': subject,
            'body': body,
            'headers': headers,
            'attachments': attachments
        }

    def _process_msg_file(self, file_path: str) -> Dict[str, Any]:
        """Parse .msg file (Outlook)"""
        if not extract_msg:
            raise ImportError("extract_msg library is required to parse .msg files")
        
        msg = extract_msg.Message(file_path)
        subject = msg.subject or ''
        body = msg.body or ''
        headers = {
            'from': msg.sender,
            'to': msg.to,
            'cc': msg.cc,
            'date': msg.date
        }
        attachments = [att.longFilename or att.shortFilename for att in msg.attachments]

        return {
            'subject': subject,
            'body': body,
            'headers': headers,
            'attachments': attachments
        }

    def _process_text_file(self, file_path: str) -> Dict[str, Any]:
        """Parse .txt or .html file"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Basic subject guessing using regex
        subject_match = re.search(r'(Subject|SUBJECT|subject):\s*(.*)', content)
        subject = subject_match.group(2).strip() if subject_match else ''
        
        headers = {}  # Could be extended with From, To, etc.
        return {
            'subject': subject,
            'body': content,
            'headers': headers,
            'attachments': []
        }

    def _get_email_body(self, msg) -> str:
        """Extract email body from multipart or plain messages"""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    return part.get_content()
                elif content_type == 'text/html':
                    html = part.get_content()
                    return self._strip_html_tags(html)
        else:
            return msg.get_content()
        return ''

    def _strip_html_tags(self, html: str) -> str:
        """Convert HTML to plain text (basic)"""
        return re.sub(r'<[^>]+>', '', html)

    def _get_attachments(self, msg) -> list:
        """Extract attachment filenames"""
        attachments = []
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
        return attachments
