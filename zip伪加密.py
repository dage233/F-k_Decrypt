import zipfile


def modified(filename):
    with open(filename, 'rb') as f:
        r_all = f.read()
        # print(r_all)
        r_all = bytearray(r_all)
        #  504B0304后的第3、4个byte改成0000
        index = r_all.find(b'PK\x03\x04')
        if not index:
            i = index + 4
            r_all[i + 2:i + 4] = b'\x00\x00'
        #  504B0102后的第5、6个byte改成0000
        index1 = r_all.find(b'PK\x01\x02')
        if index1:
            print()
            i = index1 + 4
            r_all[i + 4:i + 6] = b'\x00\x00'
    with open('testraspberripy.zip', 'wb') as f1:
        f1.write(r_all)


def show_b2h(filename):
    with open(filename, 'rb') as f:
        r = f.read(1)
        cnt = 0
        while r:
            b = ord(r)
            print('%02x ' % (b), end='')
            cnt = cnt + 1
            if cnt % 16 == 0:
                print()
            r = f.read(1)


def unzip_file(zip_src):
    
    r = zipfile.is_zipfile(zip_src)
    if r:
        fz = zipfile.ZipFile(zip_src, 'r')
        for file in fz.namelist():
            fz.extract(file, 'result')
    else:
        print('error')


if __name__ == '__main__':
    filename = 'flag.zip'
    show_b2h(filename)
    modified(filename)
    print('修改后为:')
    show_b2h('testraspberripy.zip')

# 50 4b 03 04 文件头标记
# 14 00 解压文件所需要的pkware的版本
# 09 00 全局方式标志有无加密
# 08 00 50 a3 最后修改文件时间 日期
# 21 38 76 65 crc32
# 19 00 00 00 压缩后尺寸
# 17 00 00 00 未压缩尺寸
# 08 00 文件长度
# 00 00 扩展记录长度
