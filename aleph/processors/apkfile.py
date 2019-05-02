# -*- coding: utf8 -*-

from aleph.models import Processor

from androguard.core.bytecodes.apk import APK

class APKFile(Processor):
    """Plugin that analyze APK files and extracts static properties including:

        * manifest properties (e.g., permissions, activities)
        * class hierarchy

        Requires androguard
    """
    name = 'apkfile'
    filetypes = ['application/vnd.android.package-archive']

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

        # Extract DEX and send to pipeline
        dex = apk.get_dex()
        if dex:
            self.dispatch(dex, parent=sample['id'], filename="%s.dex" % sample['id'])

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

            # Extract certificates if APK is signed
            if apk.is_signed:
                for cert in apk.get_certificates():
                    self.dispatch(cert.contents, parent=sample['id'], filename="%s.der" % cert.sha256)

        return result
