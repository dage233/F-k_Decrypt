#!-*- coding:utf-8 -*-
import os
import requests
from io import BytesIO
from pyzbar import pyzbar
from PIL import Image, ImageEnhance
import qrcode
import sys
import time


def get_qr(text):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=2,
    )  # 设置图片格式
    
    qr.add_data(text)
    qr.make(fit=True)
    # img = qr.make_image()
    # img.save('qrcode.png')  # 生成图片
    return qr.make_image()


def get_ewm(img_adds):
    """ 读取二维码的内容： img_adds：二维码地址（可以是网址也可是本地地址 """
    if os.path.isfile(img_adds):
        # 从本地加载二维码图片
        img = Image.open(img_adds)
    else:
        # 从网络下载并加载二维码图片
        rq_img = requests.get(img_adds).content
        img = Image.open(BytesIO(rq_img))
    
    # img.show()  # 显示图片，测试用
    txt_list = pyzbar.decode(img)
    
    for txt in txt_list:
        barcodeData = txt.data.decode("utf-8")
        print(barcodeData)


if __name__ == '__main__':
    # 解析本地二维码
    get_ewm('123.png')
    
    # 解析网络二维码
    # get_ewm('')
    pass
