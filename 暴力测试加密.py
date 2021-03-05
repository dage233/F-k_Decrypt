# import tools.main
from tools.main import *

# TODO
text = '''put the text in here'''

key = '2'

ENCODE = True
DECODE = True
ENCRYPT = True
DECRYPT = True
BINARY = True

print_error = True

encode_list = ['URL-UTF8', 'URL-GB2312', 'Unicode',
               'Escape(%U)', 'HtmlEncode', 'ASCII',
               'Base16', 'Base32', 'Base36','Base58', 'Base62', 'Base64','Base85','Base91','Base92',
               'Str-Hex', 'Shellcode', 'Qwerty'
               ]

decode_list = ['URL-UTF8', 'URL-GB2312', 'Unicode',
               'Escape(%U)', 'HtmlEncode', 'ASCII',
               'Base16', 'Base32', 'Base36','Base58', 'Base62', 'Base64','Base85','Base91','Base92',
               'Hex-Str', 'Shellcode', 'Qwerty'
               ]

encrypt_list = ['Rot13', '凯撒密码', '栅栏密码',
                '培根密码', '摩斯密码', '云影密码',
                '当铺密码', '维吉尼亚密码', '埃特巴什码'
                ]
decrypt_list = ['Rot13', '凯撒密码', '栅栏密码',
                '培根密码', '摩斯密码', '移位密码',
                '云影密码', '当铺密码', '维吉尼亚密码',
                '埃特巴什码', 'brainfuck', 'ook',
                '社会主义编码'
                ]

binary_list = ['2->8', '2->10', '2->16',
               '8->2', '8->10', '8->16',
               '10->2', '10->8', '10->16',
               '16->2', '16->8', '16->10',
               '自定义']
if ENCODE:
    print('********************ENCODE********************')
    for type in encode_list:
        encode(text, type, print_data=True, print_error=print_error)
if DECODE:
    print('********************DECODE********************')
    for type in decode_list:
        decode(text, type, print_data=True, print_error=print_error)
if ENCRYPT:
    print('********************ENCRYPT********************')
    for type in encrypt_list:
        encrypt(text, type, print_data=True, print_error=print_error, key=key)
if DECRYPT:
    print('********************DECRYPT********************')
    for type in decrypt_list:
        decrypt(text, type, print_data=True, print_error=print_error, key=key)
if BINARY:
    print('********************BINARY********************')
    for type in binary_list:
        if type != '自定义':
            binary(text, type, print_data=True, print_error=print_error)
