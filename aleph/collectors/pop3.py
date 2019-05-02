#!/usr/bin/env python3
##
# Aleph v2
# POP3 SSL email collector
##
# import email
import uuid
import poplib

from aleph.models import Collector


class POP3(Collector):

    required_options = ['pop_server', 'pop_user', 'pop_password', 'pop_port']

    def collector(self):
        try:
            conn = poplib.POP3_SSL(self.options.get('pop_server'), self.options.get('pop_port'))
            conn.user(self.options.get('pop_user'))
            conn.pass_(self.options.get('pop_password'))
            self.logger.info('Connected to POP server {0}'.format(self.options.get('pop_server')))

        except Exception as err:
            self.logger.error('Failed to connect to POP server: {0}'.format(err))
            pass

        # get message count
        total = 0

        message_count, mailbox_size = conn.stat()

        if message_count > 1:
            self.logger.debug('Fetching unread messages ...')

            for i in xrange(message_count, mailbox_size, -1):
                try:
                    # read message and set to SEEN
                    raw_data = conn.retr(i)

                    # join at newlines to create readable email
                    msg_data = '\n'.join(raw_data[1])

                    # push to pipeline for analysis
                    self.logger.debug('Inserting new email into the pipeline')
                    self.dispatch(msg_data, filename=str(uuid.uud4))
                    total += 1

                except Exception as err:
                    self.logger.error('Unhandled error retreiving email messages: {0}'.format(str(err)))

            self.logger.debug('Retrieved {0} new messages'.format(total))

            self.logger.debug('Closing POP connection')
            conn.quit()

        else:
            self.logger.info('No new email messages to retrieve {0}'.format(
                self.options.get('pop_server')
            ))

            self.logger.debug('Closing POP connection')
            conn.quit()
