import sys, os, json, random
import html, string, urllib.parse
import base36,base58,base64,base91
# import base36,base58,base62,base64,base91,py3base92

import brainfuck


# 编码
def encode(text, encode_type, print_data=False, print_error=True):
    try:
        result_text = ''
        if text == '':
            return 0
        if encode_type == 'URL-UTF8':
            text = text.encode('utf-8')
            result_text = urllib.parse.quote(text)
        if encode_type == 'URL-GB2312':
            text = text.encode('gb2312')
            result_text = urllib.parse.quote(text)
        if encode_type == 'Unicode':
            text = text.encode('unicode_escape')
            result_text = str(text, encoding='utf-8')
        if encode_type == 'Escape(%U)':
            text = text.encode('unicode_escape')
            result_text = str(text, encoding='utf-8').replace('\\u', '%u')
        if encode_type == 'HtmlEncode':
            result_text = html.escape(text)
        if encode_type == 'ASCII':
            result = ''
            for i in text:
                result = str(result) + str(ord(str(i))) + ' '
            result_text = str(result)[:-1]
        if encode_type == 'Base16':
            text = base64.b16encode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if encode_type == 'Base32':
            text = base64.b32encode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if encode_type == 'Base36':
            base36_m_int = int(text)
            result_text = base36.dumps(base36_m_int)
        if encode_type == 'Base58':
            text = base58.b58encode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if encode_type == 'Base62':
            result_text=base62.encode(int(text))
        if encode_type == 'Base64':
            text = base64.b64encode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if encode_type == 'Base85':
            text = base64.b85encode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if encode_type == 'Base91':
            result_text = base91.encode(text.encode("utf-8"))
        if encode_type == 'Base92':
            result_text = py3base92.encode(text.encode("utf-8"))
        if encode_type == 'Str-Hex':
            result = ''
            for i in text:
                single = str(hex(ord(str(i))))
                result = result + single
            result_text = '0x' + (str(result)).replace('0x', '')
        if encode_type == 'Shellcode':
            result = ''
            for i in text:
                single = str(hex(ord(str(i))))
                result = result + single
            result_text = (str(result)).replace('0x', '\\x')
        if encode_type == 'Qwerty':
            str1 = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
            str2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            result_text = ""
            for s in text:
                if s != ' ':
                    result_text = result_text + str1[str2.index(s)]
                else:
                    result_text = result_text + ' '
        if print_data:
            print('{:^10}:{:^15}=> {}'.format('ENCODE', encode_type, result_text))
        return result_text
    except Exception as e:
        if print_error:
            print('{:^10}:{:^15}=> {}'.format('ERROR', encode_type, str(e)))
        return e


# 解码
def decode(text, decode_type, print_data=False, print_error=True):
    try:
        result_text = ''
        if text == '':
            return 0
        if decode_type == 'URL-UTF8':
            result_text = str(urllib.parse.unquote(text))
        if decode_type == 'URL-GB2312':
            result_text = str(urllib.parse.unquote(text, 'gb2312'))
        if decode_type == 'Unicode':
            result_text = bytes(text, encoding="utf8").decode('unicode_escape')
        if decode_type == 'Escape(%U)':
            text = text.replace('%u', '\\u').replace('%U', '\\u')
            result_text = bytes(text, encoding="utf8").decode('unicode_escape')
        if decode_type == 'HtmlEncode':
            result_text = html.unescape(text)
        if decode_type == 'ASCII':
            if ':' in text:
                text = text.split(":")
            if ' ' in text:
                text = text.split(" ")
            if ';' in text:
                text = text.split(";")
            if ',' in text:
                text = text.split(",")
            result = ''
            for i in text:
                if i != '':
                    # print(chr(int(i)))
                    result = result + chr(int(i))
            result_text = result
        if decode_type == 'Base16':
            text = base64.b16decode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if decode_type == 'Base32':
            text = base64.b32decode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if decode_type == 'Base36':
            text = base36.loads(text)
            result_text = str(text)
        if decode_type == 'Base58':
            text = base58.b58decode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if decode_type == 'Base62':
            text = base62.decode(text)
            result_text = str(text)
        if decode_type == 'Base64':
            text = base64.b64decode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if decode_type == 'Base85':
            text = base64.b85decode(text.encode("utf-8"))
            result_text = str(text, encoding='utf-8')
        if decode_type == 'Base91':
            text = base91.decode(text)
            result_text = str(text, encoding='utf-8')
        if decode_type == 'Base92':
            result_text = py3base92.decode(text)
        if decode_type == 'Hex-Str':
            text = text.replace('0x', '').replace('0X', '')
            result_text = str(bytes.fromhex(text), encoding="utf-8")
        if decode_type == 'Shellcode':
            result = ''
            text = text.split('\\x')
            for i in text:
                single = str(bytes.fromhex(i), encoding="utf-8")
                result = result + single
            result_text = str(result)
        if decode_type == 'Qwerty':
            letter = {
                'q': 'a', 'w': 'b', 'e': 'c', 'r': 'd', 't': 'e', 'y': 'f', 'u': 'g',
                'i': 'h', 'o': 'i', 'p': 'j', 'a': 'k', 's': 'l', 'd': 'm', 'f': 'n',
                'g': 'o', 'h': 'p', 'j': 'q', 'k': 'r', 'l': 's', 'z': 't',
                'x': 'u', 'c': 'v', 'v': 'w', 'b': 'x', 'n': 'y', 'm': 'z',
                
                'Q': 'A', 'W': 'B', 'E': 'C', 'R': 'D', 'T': 'E', 'Y': 'F', 'U': 'G',
                'I': 'H', 'O': 'I', 'P': 'J', 'A': 'K', 'S': 'L', 'D': 'M', 'F': 'N',
                'G': 'O', 'H': 'P', 'J': 'Q', 'K': 'R', 'L': 'S', 'Z': 'T',
                'X': 'U', 'C': 'V', 'V': 'W', 'B': 'X', 'N': 'Y', 'M': 'Z',
            }
            result_text = ''
            for i in range(0, len(text)):
                if text[i] != ' ':
                    result_text = result_text + letter.get(text[i])
                else:
                    result_text = result_text + ' '
        if print_data:
            print('{:^10}:{:^15}=> {}'.format('DECODE', decode_type, result_text))
        return result_text
    except Exception as e:
        if print_error:
            print('{:^10}:{:^15}=> {}'.format('ERROR', decode_type, str(e)))
        return str(e)


# encrypt
def encrypt(text, encrypt_type, print_data=False, print_error=True, key=0):
    try:
        result_text = ''
        if text == '':
            return 0
        if encrypt_type == 'Rot13':
            d = {chr(i + c): chr((i + 13) % 26 + c) for i in range(26) for c in (65, 97)}
            result_text = ''.join([d.get(c, c) for c in text])
        if encrypt_type == '凯撒密码':
            t = ""
            for c in text:
                if 'a' <= c <= 'z':  # str是可以直接比较的
                    t += chr(ord('a') + ((ord(c) - ord('a')) + 3) % 26)
                elif 'A' <= c <= 'Z':
                    t += chr(ord('A') + ((ord(c) - ord('A')) + 3) % 26)
                else:
                    t += c
            result_text = t
        if encrypt_type == '栅栏密码':
            if type(key != int):
                key = int(key)
            for i in range(key):
                for j in range(int(text.__len__() / key + 0.5)):
                    try:
                        result_text += text[j * key + i]
                    except:
                        pass
        if encrypt_type == '培根密码':
            CODE_TABLE = {  # 培根字典
                'aaaaa': 'a', 'aaaab': 'b', 'aaaba': 'c', 'aaabb': 'd', 'aabaa': 'e', 'aabab': 'f', 'aabba': 'g',
                'aabbb': 'h', 'abaaa': 'i', 'abaab': 'j', 'ababa': 'k', 'ababb': 'l', 'abbaa': 'm', 'abbab': 'n',
                'abbba': 'o', 'abbbb': 'p', 'baaaa': 'q', 'baaab': 'r', 'baaba': 's', 'baabb': 't', 'babaa': 'u',
                'babab': 'v', 'babba': 'w', 'babbb': 'x', 'bbaaa': 'y', 'bbaab': 'z'
            }
            str = text.lower()
            listStr = ''
            for i in str:
                if i in CODE_TABLE.values():
                    # 将键、值各化为一个列表，取出i在value的位置后根据下标找到对应的键
                    listStr += list(CODE_TABLE.keys())[list(CODE_TABLE.values()).index(i)]
            result_text = listStr.upper()  # 大写输出
        if encrypt_type == '摩斯密码':
            CODE = {'A': '.-', 'B': '-...', 'C': '-.-.',
                    'D': '-..', 'E': '.', 'F': '..-.',
                    'G': '--.', 'H': '....', 'I': '..',
                    'J': '.---', 'K': '-.-', 'L': '.-..',
                    'M': '--', 'N': '-.', 'O': '---',
                    'P': '.--.', 'Q': '--.-', 'R': '.-.',
                    'S': '...', 'T': '-', 'U': '..-',
                    'V': '...-', 'W': '.--', 'X': '-..-',
                    'Y': '-.--', 'Z': '--..',
                    '0': '-----', '1': '.----', '2': '..---',
                    '3': '...--', '4': '....-', '5': '.....',
                    '6': '-....', '7': '--...', '8': '---..',
                    '9': '----.', '?': '..--..', '/': '-..-.',
                    '()': '-.--.-', '-': '-....-', '.': '.-.-.-'
                    }
            msg = ''
            for char in text:
                if char == ' ':
                    pass
                else:
                    msg += (CODE[char.upper()] + ' ')
            result_text = msg
        if encrypt_type == '云影密码':
            charList = [chr(i) for i in range(ord('A'), ord('Z') + 1)]
            cipher = [i for i in text]
            tmp = []
            ret = []
            for i in range(len(cipher)):
                for j in range(len(charList)):
                    if charList[j] == cipher[i]:
                        tmp.append(j + 1)
            for i in tmp:
                res = ''
                if i >= 8:
                    for j in range(0, int(i / 8)):
                        res += '8'
                if i % 8 >= 4:
                    for j in range(0, int(i % 8 / 4)):
                        res += '4'
                if i % 4 >= 2:
                    for j in range(0, int(i % 4 / 2)):
                        res += '2'
                if i % 2 >= 1:
                    for j in range(0, int(i % 2 / 1)):
                        res += '1'
                ret.append(res + '0')
            result_text = ''.join(ret)[:-1]
        if encrypt_type == '当铺密码':
            try:
                mapping_data = [[], [], [], [], [], [], [], [], [], []]
                if __name__ == '__main__':
                    with open('dangpu.data', 'r', encoding='UTF-8') as f:
                        for line in f:
                            ss = line.strip('\n').split(' ')
                            mapping_data[int(ss[1]) - 1].append(ss[0])
                else:
                    with open('tools/dangpu.data', 'r', encoding='UTF-8') as f:
                        for line in f:
                            ss = line.strip('\n').split(' ')
                            mapping_data[int(ss[1]) - 1].append(ss[0])
            except:
                if print_error:
                    print('{:^10}:{:^15}{}'.format('ERROR', encrypt_type, 'dangpu.data加载错误'))
                    return 'ERROR'
            result = []
            for c in text:
                c_list = mapping_data[int(c)]
                c_index = random.randint(0, len(c_list) - 1)
                result.append(c_list[c_index])
            result_text = ''.join(result)
        if encrypt_type == '维吉尼亚密码':
            ptLen = len(text)
            keyLen = len(key)
            quotient = ptLen // keyLen  # 商
            remainder = ptLen % keyLen  # 余
            for i in range(0, quotient):
                for j in range(0, keyLen):
                    c = int((ord(text[i * keyLen + j]) - ord('a') + ord(key[j]) - ord('a')) % 26 + ord('a'))
                    # global output
                    result_text += chr(c)
            
            for i in range(0, remainder):
                c = int((ord(text[quotient * keyLen + i]) - ord('a') + ord(key[i]) - ord('a')) % 26 + ord('a'))
                # global output
                result_text += chr(c)
        if encrypt_type == '埃特巴什码':
            str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            str2 = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
            result_text = ""
            for s in text:
                if s != ' ':
                    result_text = result_text + str2[str1.index(s)]
                else:
                    result_text = result_text + ' '
        if print_data:
            print('{:^10}:{:^15}=> {}'.format('ENCRYPT', encrypt_type, result_text))
        return result_text
    except Exception as e:
        if print_error:
            if encrypt_type == '栅栏密码' or encrypt_type == '埃特巴什码':
                print('{:^10}:{}'.format('ERROR', encrypt_type), e)
            else:
                print('{:^10}:{}(encrypt_numb:{})'.format('ERROR', encrypt_type, key), e)
        return 'ERROR'


# decrypt
def decrypt(text, decrypt_type, print_data=False, print_error=True, key=0):
    try:
        result_text = ''
        if text == '':
            return 0
        if decrypt_type == 'Rot13':
            PAIRS = {
                "a": "n", "b": "o", "c": "p", "d": "q", "e": "r",
                "f": "s", "g": "t", "h": "u", "i": "v", "j": "w",
                "k": "x", "l": "y", "m": "z", "n": "a", "o": "b",
                "p": "c", "q": "d", "r": "e", "s": "f", "t": "g",
                "u": "h", "v": "i", "w": "j", "x": "k", "y": "l",
                "z": "m", "A": "N", "B": "O", "C": "P", "D": "Q",
                "E": "R", "F": "S", "G": "T", "H": "U", "I": "V",
                "J": "W", "K": "X", "L": "Y", "M": "Z", "N": "A",
                "O": "B", "P": "C", "Q": "D", "R": "E", "S": "F",
                "T": "G", "U": "H", "V": "I", "W": "J", "X": "K",
                "Y": "L", "Z": "M"
            }
            result_text = "".join(PAIRS.get(c, c) for c in text)
        if decrypt_type == '凯撒密码':
            t = ""
            for c in text:
                if 'a' <= c <= 'z':  # str是可以直接比较的
                    t += chr(ord('a') + ((ord(c) - ord('a')) - 3) % 26)
                elif 'A' <= c <= 'Z':
                    t += chr(ord('A') + ((ord(c) - ord('A')) - 3) % 26)
                else:
                    t += c
            result_text = t
        if decrypt_type == '栅栏密码':
            result_text = '\n'
            lenth=text.__len__()
            for n in range(2, lenth-1):
                ans = ''
                for i in range(n):
                    for j in range(int(text.__len__() / n + 0.5)):
                        try:
                            ans += text[j * n + i]
                        except:
                            pass
                result_text += "           {} 分为{}栏\n".format(ans.ljust(lenth),str(n))
        if decrypt_type == '培根密码':
            return_str = ''
            dicts = {'aabbb': 'H', 'aabba': 'G', 'baaab': 'R', 'baaaa': 'Q', 'bbaab': 'Z', 'bbaaa': 'Y',
                     'abbab': 'N',
                     'abbaa': 'M', 'babaa': 'U', 'babab': 'V', 'abaaa': 'I', 'abaab': 'J', 'aabab': 'F',
                     'aabaa': 'E',
                     'aaaaa': 'A', 'aaaab': 'B', 'baabb': 'T', 'baaba': 'S', 'aaaba': 'C', 'aaabb': 'D',
                     'abbbb': 'P',
                     'abbba': 'O', 'ababa': 'K', 'ababb': 'L', 'babba': 'W', 'babbb': 'X'}
            sums = len(text)
            j = 5  ##每5个为一组
            for i in range(int(sums / j)):
                result = text[j * i:j * (i + 1)].lower()
                return_str += str(dicts[result], )
            result_text = return_str
        if decrypt_type == '摩斯密码':
            dict = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
                    '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
                    '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
                    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
                    '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
                    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                    '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2',
                    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
                    '--...': '7', '---..': '8', '----.': '9', '-----': '0',
                    '..--..': '?', '-..-.': '/', '-.--.-': '()', '-....-': '-',
                    '.-.-.-': '.'
                    }
            msg = ''
            s = text.split(' ')
            for item in s:
                if item != '' and item != ' ':
                    msg += (dict[item])
            result_text = msg
        if decrypt_type == '移位密码':
            inputStr = text.lower()
            caseS1 = string.ascii_lowercase * 2
            # caseS1 = string.ascii_uppercase * 2
            result_text = '\n'
            for j in range(26):
                result_list = []
                for i, num in zip(inputStr, range(len(inputStr))):
                    status = caseS1.find(i)
                    if status != -1:
                        result_list.append(caseS1[status + j])
                    else:
                        result_list.append(inputStr[num])
                text2 = ("".join(result_list), "向右偏移了{}位".format(j))
                
                result_text += '           ' + text2[0] + ' ' + text2[1] + '\n'
        if decrypt_type == '云影密码':
            charList = [chr(i) for i in range(ord('A'), ord('Z') + 1)]
            ret = []
            plaintext = [i for i in text.split('0')]
            for i in plaintext:
                tmp = 0
                for j in range(len(i)):
                    tmp += int(i[j])
                ret.append(charList[tmp - 1])
            result_text = ''.join(ret)
        if decrypt_type == '当铺密码':
            try:
                mapping_data = {}
                if __name__ == '__main__':
                    with open('dangpu.data', 'r', encoding='UTF-8') as f:
                        for line in f:
                            ss = line.strip('\n').split(' ')
                            mapping_data[ss[0]] = int(ss[1])
                else:
                    with open('tools/dangpu.data', 'r', encoding='UTF-8') as f:
                        for line in f:
                            ss = line.strip('\n').split(' ')
                        mapping_data[ss[0]] = int(ss[1])
            except:
                print('{:^10}:{:^15}{}'.format('ERROR', decrypt_type, 'dangpu.data加载错误'))
            result_text = ''.join(map(lambda x: str(mapping_data[x] - 1), text))
        if decrypt_type == '维吉尼亚密码':
            letter_list = string.ascii_uppercase
            letter_list2 = string.ascii_lowercase
            key_list = []
            for i in key:
                key_list.append(ord(i.upper()) - 65)
            flag = 0
            for cipher in text:
                if flag % len(key_list) == 0:
                    flag = 0
                if cipher.isalpha():
                    if cipher.isupper():
                        result_text += letter_list[(ord(cipher) - 65 - key_list[flag]) % 26]
                        flag += 1
                    if cipher.islower():
                        result_text += letter_list2[(ord(cipher) - 97 - key_list[flag]) % 26]
                        flag += 1
                else:
                    result_text += cipher
        if decrypt_type == '埃特巴什码':
            str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            str2 = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
            result_text = ""
            for s in text:
                if s != ' ':
                    result_text = result_text + str1[str2.index(s)]
                else:
                    result_text = result_text + ' '
        if decrypt_type == 'brainfuck':
            try:
                result_text = brainfuck.brainfuck(text)
            except:
                result_text = 'ERROR'
        if decrypt_type == 'ook':
            try:
                result_text = brainfuck.ook(text)
            except:
                result_text = 'ERROR'
        if decrypt_type == '社会主义编码':
            result_text = '开发中'
            # TODO 社会主义编码
            # try:
            #     #调用js代码
            #     if __name__=='__main__':
            #         with open('fuqiang_minzhu.js','r',encoding='utf-8') as f:
            #             context = execjs.compile(f.read())  #注意f.read()指针问题
            #             result_text=context.call('decode',[text])  #func为scripts.js中函数
            #     else:
            #         with open('tools/fuqiang_minzhu.js','r',encoding='utf-8') as f:
            #             context = execjs.compile(f.read())  #注意f.read()指针问题
            #             result_text=context.call('decode',[text])  #func为scripts.js中函数
            # except:
            #     result_text='ERROR'
        
        if print_data:
            print('{:^10}:{:^15}=> {}'.format('DECRYPT', decrypt_type, result_text))
        return result_text
    except Exception as e:
        if print_error:
            if decrypt_type == '维吉尼亚密码':
                print('{:^10}:{:^15}=> {}'.format('ERROR', decrypt_type, str(e)))
            else:
                print('{:^10}:{:^15}=> {}(encrypt_numb:{})'.format('ERROR', decrypt_type, str(e), key))
        return str(e)


# binary
def binary(text, binary_type, print_data=False, print_error=True, from_=0, to_=0):
    try:
        result_text = ''
        if text == '':
            return 0
        if binary_type == '2->8':
            result = int(text, 2)
            result_text = str(oct(result))
        if binary_type == '2->10':
            result = int(text, 2)
            result_text = str(result)
        if binary_type == '2->16':
            result_text = str(hex(int(text, 2)))
        if binary_type == '8->2':
            result = int(text, 8)
            result_text = str(bin(result))
        if binary_type == '8->10':
            result = int(text, 8)
            result_text = str(result)
        if binary_type == '8->16':
            result = int(text, 8)
            result_text = str(hex(result))
        if binary_type == '10->2':
            s = int(text)
            result_text = str(bin(s))
        if binary_type == '10->8':
            s = int(text)
            result_text = str(oct(s))
        if binary_type == '10->16':
            s = int(text)
            result_text = str(hex(s))
        if binary_type == '16->2':
            result_text = str(bin(int(text, 16)))
        if binary_type == '16->8':
            result = int(text, 16)
            result_text = str(oct(result))
        if binary_type == '16->10':
            result = int(text, 16)
            result_text = str(result)
        if binary_type == '自定义':
            try:
                if from_ != '' and to_ != '':
                    ten_num = sum([int(i) * from_ ** n for n, i in enumerate(text[::-1])])
                    a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'A', 'b', 'C', 'D', 'E', 'F']
                    b = []
                    while True:
                        s = ten_num // to_  # 商
                        y = ten_num % to_  # 余数
                        b = b + [y]
                        if s == 0:
                            break
                        ten_num = s
                    b.reverse()
                    for i in b:
                        result_text += str(a[i])
            except Exception as e:
                pass
        result_text = str(result_text).replace('0o', '').replace('0x', '').replace('0b', '')
        if print_data:
            if binary_type == '自定义':
                print('{:^10}:{:^15}=> {}'.format('BINARY', str(from_) + str(to_), result_text))
            
            else:
                print('{:^10}:{:^15}=> {}'.format('BINARY', binary_type, result_text))
        
        return result_text
    except Exception as e:
        if print_error:
            if binary_type == '自定义':
                print('{:^10}:{:^15}=> {}'.format('ERROR', binary_type, str(e)))
            else:
                print('{:^10}:{:^15}=> {}(from:{},to:{})'.format('ERROR', binary_type, str(e), from_, to_))
        return str(e)


if __name__ == '__main__':
    print('''
    功能介绍
    编码解码:URL-UTF-8    URL-GB2312    Unicode    Escape(%U)    HtmlEncode
    ACSII    Base16    Base32    Base64    Str->Hex    Shellcode    qwerty(键盘密码)

    加密解密:Rot13    凯撒密码    栅栏密码    培根密码    摩斯密码
    移位密码    云影密码    当铺密码    维尼吉亚密码    埃特巴什码
    
    进制转换:2->8    2->10    2->16    8->2    8->10    8->16
    10->2    10->8    10->16    16->2    16->8    16->10    任意进制转换
    使用方法:看源码
            ''')
