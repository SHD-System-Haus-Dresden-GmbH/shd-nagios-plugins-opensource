#!/usr/bin/python

import nagiosplugin
import argparse
import os
import time
import subprocess
import datetime
import sys

__doc__ = "SHD Nagios Plugin for checking various network shares.\nStefan Kauerauf <stefan.kauerauf@shd-online.de\nThis Plugin checks Network shares like SMB/Samba for availability,\nfilesizes and so on."

class Share(nagiosplugin.Resource):
    
    def __init__(self, args):
        self.args = args

    def probe(self):

        # make sure nothing is mounted
        self.umount(self.args)

        # mount
        mount_result = self.mount(self.args)

        # run the command for check
        check_result = self.check(self.args)
        yield nagiosplugin.Metric(self.args.command, check_result, context=self.args.command)

        # umount
        umount_result = self.umount(self.args)
        
    # mount the filesystem
    def mount(self, args):
        mountpoint = args.mountpoint
        # check if mountpoint exists
        if not os.path.isdir(mountpoint):
            raise Exception ("mountpoint don't exist! " + mountpoint)
        # check if mountpoint is writeable
        try:
            f = open(os.path.join(mountpoint, "testfile_nagios.tmp"), 'w')
            f.write('data')
            f.close()
            os.remove(os.path.join(mountpoint, "testfile_nagios.tmp"))
        except Exception:
            raise Exception ('mountpoint not writeable! ' + mountpoint)

        # mountpoint supergeil, let's mount stuff
        # check which technology is requested
        try:
            return getattr(self, "mount_" + args.fstype)(args)
        except AttributeError:
            raise Exception ("could not mount")

    def umount(self, args):
        cmdline = "fusermount -u " + args.mountpoint
        p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.wait()

    def mount_sshfs(self, args):
        cmdline = "echo '" + args.password + "' | sshfs " + args.user + "@" + args.host + ":" + args.target + " " + args.mountpoint + " -o password_stdin,uid=`id -u nagios`,gid=`id -g nagios`"
        p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.wait()

    def mount_smb(self, args):
        cmdline = 'mount -t cifs //' + args.host + "/" + args.target + " " + args.mountpoint + " -o username='" + args.user + "',domain='" + args.domain + "',password='" + args.password + "'"
        p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.wait()

    def mount_nfs(self, args):
        cmdline = 'mount ' + args.host + ":/" + args.target + " " + args.mountpoint
        p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.wait()

    def check(self, args):
        try:
            return getattr(self, "check_" + args.command)(args)
        except AttributeError:
            raise Exception("Command not supported!")

    def check_fileExist(self, args):
        if args.cfile == "":
            raise Exception("File argument missing")
        return os.path.isfile(os.path.join(args.mountpoint, args.cfile))
    
    def check_dirExist(self, args):
        if args.cdir == "":
            raise Exception("Directory argument missing")
        return os.path.isdir(os.path.join(args.mountpoint, args.cdir))

    def check_dirEmpty(self, args):
        if args.cdir == "":
            raise Exception("Directory argument missing")
        path = os.path.join(args.mountpoint, args.cdir)
        if os.listdir(path) == []:
            return True
        else:
            return False

    def check_dirFileCount(self, args):
        if args.cdir == "":
            raise Exception("Directory argument missing")
        path = os.path.join(args.mountpoint, args.cdir)
        count = 0
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)):
                count = count + 1 
        return count

    def check_dirDirCount(self, args):
        if args.cdir == "":
            raise Exception("Directory argument missing")
        path = os.path.join(args.mountpoint, args.cdir)
        count = 0
        for i in os.listdir(path):
            if os.path.isdir(os.path.join(path, i)):
                count = count + 1 
        return count

    def check_dirContainsFileWithString(self, args):
        if args.cfile == "":
            raise Exception("File argument missing")
        if args.sstring == "":
            raise Exception("Search String argument missing")
        path = os.path.join(args.mountpoint, args.cdir)
        for i in os.listdir(path):
            if os.path.isfile(os.path.join(path, i)):
                f = file.open(path, "r")
                if args.sstring in f.read():
                    return True
        return False

    def check_fileSize(self, args):
        if args.cfile == "":
            raise Exception("File argument missing")
        path = os.path.join(args.mountpoint, args.cfile)
        return os.path.getsize(path)

    def check_fileAge(self, args):
        if args.cfile == "":
            raise Exception("File argument missing")
        path = os.path.join(args.mountpoint, args.cfile)
        ctime = os.path.getctime(path)
        time = datetime.datetime.now().time()
        return time - ctime

    def check_fileContainsString(self, args):
        if args.cfile == "":
            raise Exception("File argument missing")
        if args.sstring == "":
            raise Exception("Search String argument missing")
        path = os.path.join(args.mountpoint, args.cfile)
        f = file.open(path, "r")
        if args.sstring in f.read():
            return True
        return False

    def check_shareFreeSpace(self, args):
        path = args.mountpoint
        stat = os.statvfs(path)
        print stat.f_bsize * stat.f_bavail

    def check_shareUsedSpace(self, args):
        path = args.mountpoint
        stat = os.statvfs(path)
        print stat.f_bsize * (stat.f_blocks - stat.f_bfree)

    def check_shareWriteable(self, args):
        path = args.mountpoint
        try:
            f = file.open(os.path.join(path, "tmp.tmp"), "w")
            f.write("test")
            f.close()
        except Exception:
            return False
        return True

    def check_dirWriteable(self, args):
        if args.cdir == "":
            raise Exception("Directory argument missing")
        path = os.path.join(args.mountpoint, args.cdir)
        try:
            f = file.open(os.path.join(path, "tmp.tmp"), "w")
            f.write("test")
            f.close()
        except Exception:
            return False
        return True


class ShareSummary(nagiosplugin.Summary):

    def __init__(self, args):
        self.args = args

    def ok(self, results):
        if not self.args.omessage == "ok":
            return self.args.omessage + " - " + str(results[self.args.command].metric)
        return str(results[self.args.command].metric)

    def problem(self, results):
        if not self.args.pmessage == "nok":
            return self.args.pmessage + " - " + str(results[self.args.command].metric)
        return str(results[self.args.command].metric)

def excepthandler(etype, value, tb):
    print("ERROR: " + etype + " " + value)

@nagiosplugin.guarded
def main():

    #parsing arguments
    argparser = argparse.ArgumentParser(description=__doc__)
    argparser.add_argument('-H', '--host', dest='host', default='localhost', help='Hostname or IP Address')
    argparser.add_argument('-u', '--username', dest='user', help='username')
    argparser.add_argument('-p', '--password', dest='password', help='password')
    argparser.add_argument('-D', '--domain', dest='domain', help='domain/workgroup')

    argparser.add_argument('-S', '--sharetype', dest='fstype', help='sharetype: smb, ssh,...')

    argparser.add_argument('-t', '--target', dest='target', help='target url without host')
    argparser.add_argument('-m', '--mountpoint', dest='mountpoint', help='mountpoint (nagios user must have write permissions to this directory')

    argparser.add_argument('-r', '--runcommand', dest='command', help='wich check')

    argparser.add_argument('-f', '--file', dest='cfile', help='specific file in share')
    argparser.add_argument('-d', '--dir', dest='cdir', help='specific directory in share')
    argparser.add_argument('-s', '--searchstring', dest='sstring', help='string for searching')


    argparser.add_argument('-c', '--critical')
    argparser.add_argument('-w', '--warning')

    argparser.add_argument('-P', '--problemMessage', dest='pmessage', help='Output for nok', default="nok")
    argparser.add_argument('-O', '--okMessage', dest='omessage', help='Output for ok', default="ok")

    args = argparser.parse_args()
    
    check = nagiosplugin.Check(Share(args), nagiosplugin.ScalarContext(args.command, args.warning, args.critical), ShareSummary(args))
    check.main()

if __name__ == '__main__':
    sys.excepthook = excepthandler
    main()
