# -*- coding: utf8 -*-

from aleph.common.base import ProcessorBase

from androguard.core.bytecodes.apk import APK

class APKFileProcessor(ProcessorBase):
    """Plugin that analyze APK files and extracts static properties including:

        * manifest properties (e.g., permissions, activities)
        * class hierarchy

        Requires androguard
    """
    name = 'apkfile'
    mimetypes = ['application/vnd.android.package-archive']

    def parse_apk(self, data):

        try:
            apk = APK(data, raw=True)
            if apk.is_valid_APK():
                return apk
            else:
                self.logger.debug("Zip file %s is not a valid APK file" % self.sample.path)
        except Exception as ex:
            self.logger.warning('Could not parse %s because of %s', self.sample.path, ex)

        return None

    def process(self, sample):

        data = sample['data']
        result = None

        apk = self.parse_apk(data)

        if apk:
            result = {
            'min_sdk_version': apk.get_min_sdk_version(),
            'target_sdk_version': apk.get_max_sdk_version(),
            'target_sdk_version': apk.get_target_sdk_version(),
            'package': apk.get_package(),
            'services': apk.get_services(),
            'main_activity': apk.get_main_activity(),
            'receivers': apk.get_receivers(),
            'providers': apk.get_providers(),
            'permissions': apk.get_permissions(),            
            'files': apk.get_files(),            
            }
            
            self.add_tag('apk')

        return result
