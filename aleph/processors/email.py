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

    def check_spoofing(self, headers):
        """Check common headers for signs of spoofing"""

        check = ['Sender', 'Reply-To', 'Return-Path']

        for item, hdr in zip(check, headers):
            if hdr['name'] == 'From' and hdr['name']['From'] != '':
                if hdr['value'] != item:
                    self.add_tag('possible_spoofing')

    def get_attachments(self, msg, sample_id):
        """Recursively read multi-part email to get all attachments"""

        if msg.is_multipart():
            for part in msg.get_payload():
                self.get_attachment(part, sample_id)
        else:
            if 'Content-Disposition' in msg and msg.get_content_type() != 'text/plain':
                file_name = msg.get_filename('')
                if file_name != '':
                    file_name = self.decode_field(file_name)

                    try:
                        file_name = file_name.decode('utf-8', errors='replace')
                    except Exception as err:
                        pass

                    file_data = msg.get_payload(decode=True)
                    self.dispatch(file_data, parent=sample_id, filename=file_name)

    def decode_field(self, field):
        """Decode various email fields"""

        _text = field

        try:
            decoded = email.Header.decode_header(field)
            _text, charset = decoded[0]
        except email.errors.HeaderParseError:
            _text, charset = None, None

        if charset:
            try:
                _text = self.decode_string(_text, charset)
            except UnicodeDecodeError:
                pass

        try:
            _text = self.decode_value(_text)
        except UnicodeDecodeError:
            _text = self.decode_string(_text, 'latin-1')

        return _text

    def decode_string(self, string, encoding):
        """Decode weird email strings found in RFC2822 / eml files"""

        try:
            value = string.decode(encoding)
        except UnicodeDecodeError:
            enc = chardet.detect(string)

            try:
                if not (enc['confidence'] == 1 and enc['encoding'] == 'ascii'):
                    value = value.decode(enc['encoding'])
                else:
                    value = value.decode('ascii', 'ignore')
            except UnicodeDecodeError:
                value = self.force_decode(string)

        return value

    def decode_value(self, string):
        """Decode email encoded field values to remove junk data"""

        if not self.re_encoded_string.search(string):
            return string

        string_ = u''
        for line in string.replace('\r', '').split('\n'):
            line_ = u''

            for text in re.split(r'([ \t])', line):
                if '=?' in text:
                    for m in self.re_quoted_string.finditer(text):
                        match_s, method = m.groups()

                        if '=?' in match_s:
                            if method:
                                if method.lower() == 'q':
                                    text = self.q_value_decode(match_s)
                                elif method.lower() == 'b':
                                    text = self.b_value_decode(match_s)
                                else:
                                    self.logger.error('caught unknown method: {0}'.format(method))
                            else:
                                text = match_s

                            text = text.replace('_', ' ')
                            if text[0] == ' ':
                                text = text[1:]
                        else:
                            line_ += match_s

                line_ += text

            if len(string_) > 0 and not (string_[-1] == ' ' or line_[0] == ' '):
                string_ += ' '
            string_ += line_

        return string_
