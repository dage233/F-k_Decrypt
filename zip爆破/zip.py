#!/usr/bin/env
# coding=UTF-8
import zipfile
import threading
import os
import sys
class CrackZip:
    def __init__(self):
        self._result = None
    def run(self,zFile,password):
        try:
            zFile.extractall(pwd=password)
            print("Found Passwd:",password)
            print('Password=',password)
            self._result=password
        except:
            pass
    def getPass(self):
        return self._result

def checkFile(path):
    flag=False
    if not os.path.isfile(path):
        flag=False
        print('[-] %s文件不存在',path)
    return flag
def main():
    cz=CrackZip()
    if len(sys.argv)>=3:
        zipPath=sys.argv[1]
        dictionaryPath=sys.argv[2]
        flag=(len(sys.argv)>3 and sys.argv[3]=='-t')
        typeName=None
        if not checkFile(dictionaryPath):
            if dictionaryPath[-3:]!='txt':
                print('字典不是txt文件')
                return
        if not checkFile(zipPath):
            if zipPath[-3:]!='zip':
                print('只能爆破zip文件')
                return
        zFile=zipfile.ZipFile(zipPath,'r')
        passFile=open(dictionaryPath,'r')
        for line in passFile.readlines():
            password=line.strip('\n').encode('utf-8')
            if flag:
                False
                t=threading.Thread(target=cz.run,args=(zFile,password))
                t.start()
            else:
                cz.run(zFile,password)
                password=cz.getPass()
                typeName='SingleThread'
                if password:
                    return
        if typeName=='SingleThread':
            print("字典里找不到密码")
    else:
        print('命令不正确，格式为：python zip.py zipPath dictionaryPath')
        return
if __name__=='__main__':
    main()