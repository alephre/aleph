import boto3

from aleph.common.base import Collector


class S3Collector(Collector):
    """Collect samples from an AWS S3 Bucket"""

    session = None

    required_options = [
        'bucket'
        'access_key',
        'secret_key'
    ]

    def collect(self):
        """Fetch all objects in a Bucket and process as samples"""
        try:
            for obj in self.bucket.objects.all():
                filename = obj.key

                self.logger.info('Collecting object {0} from S3 bucket {1}'.format(filename, self.options.get('bucket')))
                document = self.engine.Object(self.options.get('bucket'), filename).get()
                object_data = document['Body'].read()

                self.logger.debug('Inserting sample {0} into the pipeline'.format(filename))
                self.dispatch(object_data, filename=filename)

                if self.remove_objects:
                    to_delete = [{'Key': filename}]
                    self.logger.debug('Removing object {0} from S3 bucket {1}'.format(filename, self.options.get('bucket')))
                    try:
                        resp = self.bucket.delete_objects(Delete={'Objects': to_delete})
                        if isinstance(resp, dict):
                            if 'ResponseMetadata' in resp:
                                if resp['ResponseMetadata']['HTTPStatusCode'] != 200:
                                    self.logger.error('Failed to remove object {0} from S3 bucket {1}'.format(filename, self.options.get('bucket')))
                    except Exception as err:
                        self.logger.error('Failed to remove object {0} from S3 bucket {1}: {2}'.format(filename, self.options.get('bucket'), str(err)))

        except Exception as err:
            self.logger.error('Unhandled exception collecting objects from S3 bucket {0}: {1}'.format(self.options.get('bucket'), str(err)))
            pass

    def setup(self):
        """Build session to AWS and verify bucket settings"""
        self.session = boto3.session.Session(
            aws_access_key_id=self.options.get('access_key'),
            aws_secret_access_key=self.options.get('secret_key')
        )

        self.engine = self.session.resource('s3')

        if not self.engine.Bucket(self.options.get('bucket')) in [bucket.name for bucket in self.engine.buckets.all()]:
            self.logger.error('S3 Storage bucket does not exist: %s' % self.options.get('bucket'))
            return False

        self.bucket = self.engine.get_bucket(self.options.get('bucket'))

        self.remove_objects = False
        if self.options.get('remove_objects') == 'true':
            self.remove_objects = True
