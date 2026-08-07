import malwoverview.modules.configvars as cv
from malwoverview.utils.colors import mycolors, printr, strip_json_escapes, bullet
from malwoverview.utils.hash import sha256hash
from malwoverview.modules.hybrid import HybridAnalysisExtractor
import requests
import subprocess
import threading
import json
import time
import os
from malwoverview.utils.output import add_records, collector
from malwoverview.utils.session import create_session, failure_message


PKG_COL_WIDTH = 50
PKG_COL_WIDTH_HA = 40

HA_TABLE_COLUMNS = (PKG_COL_WIDTH_HA, 66, 12, 10, 5, 14, 14)
HA_TABLE_WIDTH = sum(HA_TABLE_COLUMNS)
VT_TABLE_COLUMNS = (PKG_COL_WIDTH, 66, 12)
VT_TABLE_WIDTH = sum(VT_TABLE_COLUMNS)


SHA256_ALLOWED = set('0123456789abcdefABCDEF')


def _valid_sha256(value):
    return bool(value) and len(value) == 64 and set(value) <= SHA256_ALLOWED


def truncate_pkg(text, width=PKG_COL_WIDTH):
    text = str(text)
    if len(text) <= width:
        return text
    if '|' in text and width >= 12:
        head = (width - 3) // 2
        tail = width - 3 - head
        return text[:head] + '...' + text[-tail:]
    return text[:width - 3] + '...'


class androidVTThread(threading.Thread):
    def __init__(self, key, package, extractor):
        threading.Thread.__init__(self)
        self.key = key
        self.package = package
        self.extractor = extractor

    def run(self):
        key1 = self.key
        package1 = self.package

        myhash = key1
        vtfinal = self.extractor.virustotal.vtcheck(myhash, 0)

        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-50s" % truncate_pkg(package1)), end=' ')
            print((mycolors.foreground.pink + "%-65s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.lightcyan + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.blue + "%-50s" % truncate_pkg(package1)), end=' ')
            print((mycolors.foreground.purple + "%-65s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))


class quickHAAndroidThread(threading.Thread):
    def __init__(self, key, package, extractor):
        threading.Thread.__init__(self)
        self.key = key
        self.package = package
        self.extractor = extractor

    def run(self):
        key1 = self.key
        package1 = self.package

        myhash = key1
        result = self.extractor.quickhashowAndroid(myhash)

        (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections) = result

        if (cv.bkg == 1):
            print((mycolors.foreground.lightblue + "%-40s" % truncate_pkg(package1, PKG_COL_WIDTH_HA)), end=' ')
            print((mycolors.foreground.yellow + "%-64s" % key1), end=' ')
            print((mycolors.foreground.lightcyan + "%9s" % final), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.lightcyan + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.lightcyan + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.yellow + "%7s" % totalsignatures), end='')
            if (threatscore == 'None'):
                print((mycolors.foreground.lightred + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.lightred + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.lightred + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.yellow + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.lightcyan + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')
        else:
            print((mycolors.foreground.blue + "%-40s" % truncate_pkg(package1, PKG_COL_WIDTH_HA)), end=' ')
            print((mycolors.foreground.blue + "%-64s" % key1), end=' ')
            print((mycolors.foreground.blue + "%9s" % final), end='')
            if (avdetect == 'None'):
                print((mycolors.foreground.purple + "%7s" % avdetect), end='')
            else:
                print((mycolors.foreground.purple + "%6s%%" % avdetect), end='')
            print((mycolors.foreground.blue + "%7s" % totalsignatures), end='')
            if (threatscore == 'None'):
                print((mycolors.foreground.red + "%12s" % threatscore), end='')
            else:
                print((mycolors.foreground.red + "%8s/100" % threatscore), end='')
            if (verdict == "malicious"):
                print((mycolors.foreground.red + "%20s" % verdict), end='\n')
            elif (verdict == "suspicious"):
                print((mycolors.foreground.blue + "%20s" % verdict), end='\n')
            elif (verdict == "no specific threat"):
                print((mycolors.foreground.blue + "%20s" % verdict), end='\n')
            else:
                verdict = 'not analyzed yet'
                print((mycolors.reset + "%20s" % verdict), end='\n')


class AndroidExtractor():
    def __init__(self, hybrid, virustotal):
        self.hybrid = hybrid
        self.virustotal = virustotal

    def quickhashowAndroid(self, filehash, user_agent='Falcon Sandbox'):
        haurl = HybridAnalysisExtractor.haurl

        hatext = ''
        haresponse = ''
        final = 'Yes'
        verdict = '-'
        avdetect = '0'
        totalsignatures = '-'
        threatscore = '-'
        totalprocesses = '-'
        networkconnections = '-'

        self.hybrid.requestHAAPI()

        try:
            resource = filehash
            requestsession = create_session()
            requestsession.headers.update({'user-agent': user_agent})
            requestsession.headers.update({'api-key': self.hybrid.HAAPI})
            requestsession.headers.update({'content-type': 'application/x-www-form-urlencoded'})
            finalurl = '/'.join([haurl, 'report', 'summary'])
            resource1 = resource + ":200"
            datahash = {
                'hashes[0]': resource1
            }

            haresponse = requestsession.post(url=finalurl, data=datahash)
            hatext = strip_json_escapes(json.loads(haresponse.text))
            add_records('android', 'quickhashowAndroid', hatext)

            rc = str(hatext)

            if 'message' in rc:
                final = 'Not Found'
                return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

            if 'verdict' in hatext[0]:
                verdict = str(hatext[0]['verdict'])
            else:
                verdict = ''

            if 'threat_score' in hatext[0]:
                threatscore = str(hatext[0]['threat_score'])
            else:
                threatscore = ''

            if 'av_detect' in hatext[0]:
                avdetect = str(hatext[0]['av_detect'])
            else:
                avdetect = ''

            if 'total_signatures' in hatext[0]:
                totalsignatures = str(hatext[0]['total_signatures'])
            else:
                totalsignatures = ''

            if 'total_processes' in hatext[0]:
                totalprocesses = str(hatext[0]['total_processes'])
            else:
                totalprocesses = ''

            if 'total_network_connections' in hatext[0]:
                networkconnections = str(hatext[0]['total_network_connections'])
            else:
                networkconnections = ''

            return (final, verdict, avdetect, totalsignatures, threatscore, totalprocesses, networkconnections)

        except (ValueError, requests.exceptions.RequestException) as e:
            print(failure_message(e, 'the Android device'))
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "Error while connecting to Hybrid-Analysis!\n"))
            else:
                print((mycolors.foreground.red + "Error while connecting to Hybrid-Analysis!\n"))
            printr()

    def checkandroidha(self, key, package):
        if len(key) == 0 or len(package) == 0:
            return None

        thread = quickHAAndroidThread(key, package, self)
        thread.start()
        if cv.windows:
            thread.join()
        return thread

    def checkandroidvt(self, key, package):
        if len(key) == 0 or len(package) == 0:
            return

        key1 = key
        vtfinal = self.virustotal.vtcheck(key1, 0)
        if (cv.bkg == 1):
            print((mycolors.foreground.yellow + "%-50s" % truncate_pkg(package)), end=' ')
            print((mycolors.foreground.pink + "%-65s" % key1), end=' ')
            print((mycolors.foreground.lightred + "%8s" % vtfinal + mycolors.reset))
        else:
            print((mycolors.foreground.blue + "%-50s" % truncate_pkg(package)), end=' ')
            print((mycolors.foreground.purple + "%-65s" % key1), end=' ')
            print((mycolors.reset + mycolors.foreground.red + "%8s" % vtfinal + mycolors.reset))

    def checkandroidvtx(self, key, package):
        if len(key) == 0 or len(package) == 0:
            return None

        thread = androidVTThread(key, package, self)
        thread.start()
        if (cv.windows == 1):
            thread.join()
        return thread

    APK_PATH_ALLOWED = set('/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-~=')
    PKG_NAME_ALLOWED = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._')

    @staticmethod
    def _valid_apk_path(apk_path):
        if not apk_path:
            return False
        if not apk_path.startswith('/data/app/') or not apk_path.endswith('.apk'):
            return False
        if '..' in apk_path.split('/'):
            return False
        return all(c in AndroidExtractor.APK_PATH_ALLOWED for c in apk_path)

    @staticmethod
    def _parse_packages(output):
        packages = {}
        if not output:
            return packages

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith('package:'):
                continue

            body = line[len('package:'):]
            apk_path, sep, pkg_name = body.rpartition('=')
            if not sep or not pkg_name:
                continue
            if not AndroidExtractor._valid_apk_path(apk_path):
                continue
            if not all(c in AndroidExtractor.PKG_NAME_ALLOWED for c in pkg_name):
                continue

            packages[pkg_name] = apk_path

        return packages

    @staticmethod
    def _parse_paths(output):
        paths = []
        if not output:
            return paths

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith('package:'):
                continue

            apk_path = line[len('package:'):].strip()
            if not AndroidExtractor._valid_apk_path(apk_path):
                continue
            if apk_path not in paths:
                paths.append(apk_path)

        return paths

    @staticmethod
    def _apk_label(pkg_name, apk_path, multiple):
        if not multiple:
            return pkg_name
        return pkg_name + '|' + os.path.basename(apk_path)

    def _adb_not_found_msg(self):
        if (cv.bkg == 1):
            print(mycolors.foreground.lightred + "\nThe 'adb' tool was not found in your PATH. Install Android platform-tools and make sure 'adb' is reachable.\n")
        else:
            print(mycolors.foreground.red + "\nThe 'adb' tool was not found in your PATH. Install Android platform-tools and make sure 'adb' is reachable.\n")
        printr()

    def _no_packages_msg(self):
        if (cv.bkg == 1):
            print(mycolors.foreground.lightred + "\nNo third-party packages were found. Is a device connected and authorized? Check with 'adb devices'.\n")
        else:
            print(mycolors.foreground.red + "\nNo third-party packages were found. Is a device connected and authorized? Check with 'adb devices'.\n")
        printr()

    def _list_device_packages(self, adb_comm="adb"):
        try:
            myconn = subprocess.run([adb_comm, "shell", "pm", "list", "packages", "-f", "-3"], capture_output=True)
        except FileNotFoundError:
            self._adb_not_found_msg()
            return None

        output = myconn.stdout.decode(errors='ignore')
        return self._parse_packages(output)

    def _list_package_apks(self, pkg_name, adb_comm="adb"):
        try:
            myconn = subprocess.run([adb_comm, "shell", "pm", "path", pkg_name], capture_output=True)
        except FileNotFoundError:
            return []

        return self._parse_paths(myconn.stdout.decode(errors='ignore'))

    def _list_device_apks(self, adb_comm="adb"):
        packages = self._list_device_packages(adb_comm)
        if packages is None:
            return None

        entries = []
        for pkg_name, base_path in packages.items():
            paths = self._list_package_apks(pkg_name, adb_comm)
            if base_path not in paths:
                paths.insert(0, base_path)
            multiple = len(paths) > 1
            for apk_path in paths:
                label = self._apk_label(pkg_name, apk_path, multiple)
                entries.append((label, pkg_name, apk_path, apk_path != base_path))

        return entries

    def _report_apk_inventory(self, entries, width):
        packages = len({pkg_name for _, pkg_name, _, _ in entries})
        splits = len(entries) - packages
        if splits <= 0:
            return
        message = "Found %d APK file(s) across %d package(s): %d base and %d split APK(s). All of them are hashed." % (
            len(entries), packages, packages, splits)
        print()
        print(bullet(message, width, mycolors.foreground.neutral(cv.bkg)))

    def checkandroid(self, engine):
        adb_comm = "adb"

        entries = self._list_device_apks(adb_comm)
        if entries is None:
            return

        dictAndroid = {}
        metadata = {}
        for label, pkg_name, apk_path, is_split in entries:
            myconn3 = subprocess.run([adb_comm, "shell", "sha256sum", apk_path], text=True, capture_output=True)
            hashout = (myconn3.stdout or '').strip()
            if not hashout:
                continue
            sha256 = hashout.split(" ")[0].strip()
            if _valid_sha256(sha256):
                dictAndroid[label] = sha256
                metadata[label] = (pkg_name, apk_path, is_split)

        if not dictAndroid:
            self._no_packages_msg()
            return

        for label, sha256 in dictAndroid.items():
            pkg_name, apk_path, is_split = metadata[label]
            collector.add({
                'service': 'android',
                'query_type': 'checkandroid',
                'engine': engine,
                'package': pkg_name,
                'apk': os.path.basename(apk_path),
                'split': is_split,
                'sha256': sha256,
            })

        if (engine == 1):
            print(mycolors.reset + "\n")
            print("Package".center(HA_TABLE_COLUMNS[0]) + "Hash".center(HA_TABLE_COLUMNS[1]) + "Found?".center(HA_TABLE_COLUMNS[2]) + "AVdet".center(HA_TABLE_COLUMNS[3]) + "Sigs".center(HA_TABLE_COLUMNS[4]) + "Score".center(HA_TABLE_COLUMNS[5]) + "Verdict".center(HA_TABLE_COLUMNS[6]))
            print(HA_TABLE_WIDTH * '-')
            threads = []
            for key, value in dictAndroid.items():
                thread = self.checkandroidha(value, key)
                if thread is not None:
                    threads.append(thread)
            for thread in threads:
                thread.join()
            self._report_apk_inventory(entries, HA_TABLE_WIDTH)

        if (engine == 2):
            tm1 = 0
            print(mycolors.reset + "\n")
            print("Package".center(VT_TABLE_COLUMNS[0]) + "Hash".center(VT_TABLE_COLUMNS[1]) + "Virus Total".center(VT_TABLE_COLUMNS[2]))
            print(VT_TABLE_WIDTH * '-')
            for key, value in dictAndroid.items():
                tm1 = tm1 + 1
                if tm1 % 4 == 0:
                    time.sleep(61)
                self.checkandroidvt(value, key)
            self._report_apk_inventory(entries, VT_TABLE_WIDTH)

        if (engine == 3):
            print(mycolors.reset + "\n")
            print("Package".center(VT_TABLE_COLUMNS[0]) + "Hash".center(VT_TABLE_COLUMNS[1]) + "Virus Total".center(VT_TABLE_COLUMNS[2]))
            print(VT_TABLE_WIDTH * '-')
            threads = []
            for key, value in dictAndroid.items():
                thread = self.checkandroidvtx(value, key)
                if thread is not None:
                    threads.append(thread)
            for thread in threads:
                thread.join()
            self._report_apk_inventory(entries, VT_TABLE_WIDTH)

    def _pull_apk(self, package, adb_comm="adb"):
        packages = self._list_device_packages(adb_comm)
        if packages is None:
            return None

        apk_path = None
        chosen = None
        for pkg_name, path in packages.items():
            if package == pkg_name or package in pkg_name or package in path:
                apk_path = path
                chosen = pkg_name
                break

        if not apk_path:
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nFile not found on device!\n"))
            else:
                print((mycolors.foreground.red + "\nFile not found on device!\n"))
            printr()
            return None

        allapks = self._list_package_apks(chosen, adb_comm)
        if len(allapks) > 1:
            message = "\nThe package %s is a split APK with %d files. Only %s is being sent.\n" % (
                chosen, len(allapks), os.path.basename(apk_path))
            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + message + mycolors.reset)
            else:
                print(mycolors.foreground.purple + message + mycolors.reset)

        subprocess.run([adb_comm, "pull", apk_path], capture_output=True)

        localname = os.path.basename(apk_path)
        targetfile = os.path.basename(chosen) + ".apk"

        if not os.path.isfile(localname):
            if (cv.bkg == 1):
                print((mycolors.foreground.lightred + "\nFailed to pull the APK from the device!\n"))
            else:
                print((mycolors.foreground.red + "\nFailed to pull the APK from the device!\n"))
            printr()
            return None

        os.replace(localname, targetfile)
        return targetfile

    def sendandroidha(self, package, xx=3):
        targetfile = self._pull_apk(package)
        if not targetfile:
            return

        try:
            self.hybrid.hafilecheck(targetfile, xx=xx)
        finally:
            if os.path.isfile(targetfile):
                os.remove(targetfile)

    def sendandroidvt(self, package):
        targetfile = self._pull_apk(package)
        if not targetfile:
            return

        try:
            myhash = sha256hash(targetfile)
            self.virustotal.vtuploadfile(targetfile)
            if (cv.bkg == 1):
                print(mycolors.foreground.yellow + "\tWaiting for 120 seconds...\n")
            if (cv.bkg == 0):
                print(mycolors.foreground.purple + "\tWaiting for 120 seconds...\n")
            time.sleep(120)
            self.virustotal.vthashwork(myhash, 1)
        finally:
            if os.path.isfile(targetfile):
                os.remove(targetfile)
