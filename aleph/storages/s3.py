import boto3

from aleph.common.base import StorageBase

class S3Storage(StorageBase):

    """Store and retrieve samples from an AWS S3 Bucket"""

    session = None

    required_options = [
        'bucket',
        'access_key',
        'secret_key'
    ]

    def retrieve(self, sample_id):
        """Download a sample from your S3 bucket"""

        try:

            bucket_key = '%s.sample' % sample_id
            document = self.engine.Object(self.options.get('bucket'), bucket_key).get()
            document_data = document['Body'].read()

            return document_data

        except Exception as e:
            self.logger.error('Error retrieving sample %s: %s' % (sample_id, str(e)))
            return False

    def store(self, sample_id, data):
        """Upload a sample to an S3 bucket"""

        try:

            bucket_key = '%s.sample' % sample_id
            document = self.engine.Object(self.options.get('bucket'), bucket_key).put(Body=data)

            return True

        except Exception as e:
            self.logger.error('Error storing sample %s: %s' % (sample_id, str(e)))
            return False

    def setup(self):

        self.session = boto3.session.Session(
            aws_access_key_id=self.options.get('access_key'),
            aws_secret_access_key=self.options.get('secret_key')
        )

        self.engine = self.session.resource('s3')

        if not self.engine.Bucket(self.options.get('bucket')) in [bucket.name for bucket in self.engine.buckets.all()]:
            self.logger.error('S3 Storage bucket does not exist: %s' % self.options.get('bucket'))
            return False

