import email
import tempfile
from aleph.common.base import ProcessorBase

class EmailProcessor(ProcessorBase):

    name = 'email'
    mimetypes = ['message/rfc822']

    def process(self, sample):

        file_content = sample['data']
        mail = email.message_from_bytes(file_content)

        # Get attachments
        for part in mail.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
 
            if filename:
                file_data = part.get_payload(decode=True)
                self.dispatch(file_data, parent=sample['id'], filename=filename)

        headers = []
        for item in mail.items():
            headers.append({'name': item[0], 'value': item[1]})

        return {
            'headers': headers,
            'from': mail.get('From'),
            'to': mail.get('To'),
            'subject': mail.get('Subject'),
            }
