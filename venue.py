import base64
import random
import time
import requests
import json
import configparser
import hashlib
import os
from typing import List, Dict
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import sys
import gmssl.sm2 as sm2
from base64 import b64encode, b64decode
import traceback
import gzip
"""
加密模式：sm2非对称加密sm4密钥
"""
# 偏移量
# default_iv = '\1\2\3\4\5\6\7\x08' 失效

# 加载配置文件
cfg_path = "./config.ini"
conf = configparser.ConfigParser()
conf.read(cfg_path, encoding="utf-8")

# 学校、keys和版本信息
my_host = conf.get("Yun", "school_host")  # 学校的host
default_key = conf.get("Yun", "CipherKey")  # 加密密钥
CipherKeyEncrypted = conf.get("Yun", "CipherKeyEncrypted")  # 加密密钥的sm2加密版本
my_app_edition = conf.get("Yun", "app_edition")  # app版本（我手机上是3.0.0）

# 用户信息，包括设备信息
my_token = conf.get("User", 'token')  # 用户token
my_device_id = conf.get("User", "device_id")  # 设备id （据说很随机，抓包搞几次试试看）
my_key = conf.get("User", "map_key")  # map_key是高德地图的开发者密钥
my_device_name = conf.get("User", "device_name")  # 手机名称
my_sys_edition = conf.get("User", "sys_edition")  # 安卓版本（大版本）
my_utc = conf.get("User", "utc")
my_uuid = conf.get("User", "uuid")
my_sign = conf.get("User", "sign")

PUBLIC_KEY = b64decode(conf.get("Yun", "PublicKey"))
PRIVATE_KEY = b64decode(conf.get("Yun", "PrivateKey"))

md5key = conf.get("Yun", "md5key")
platform = conf.get("Yun", "platform")


def string_to_hex(input_string):
    # 将字符串转换为十六进制表示，然后去除前缀和分隔符
    hex_string = hex(int.from_bytes(input_string.encode(), 'big'))[2:].upper()
    return hex_string


def bytes_to_hex(input_string):
    # 将字符串转换为十六进制表示，然后去除前缀和分隔符
    hex_string = hex(int.from_bytes(input_string, 'big'))[2:].upper()
    return hex_string


sm2_crypt = sm2.CryptSM2(public_key=bytes_to_hex(PUBLIC_KEY[1:]),
                         private_key=bytes_to_hex(PRIVATE_KEY),
                         mode=1,
                         asn1=True)


def encrypt_sm4(value, SM_KEY, isBytes=False):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(SM_KEY, SM4_ENCRYPT)
    if not isBytes:
        encrypt_value = b64encode(crypt_sm4.crypt_ecb(value.encode("utf-8")))
    else:
        encrypt_value = b64encode(crypt_sm4.crypt_ecb(value))
    return encrypt_value.decode()


def decrypt_sm4(value, SM_KEY):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(SM_KEY, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(b64decode(value))
    return decrypt_value


# warning：实测gmssl的sm2加密给Java Hutool解密结果不对，所以下面的2函数暂不使用
def encrypt_sm2(info):
    encode_info = sm2_crypt.encrypt(info.encode("utf-8"))
    encode_info = b64encode(encode_info).decode()  # 将二进制bytes通过base64编码
    return encode_info


def decrypt_sm2(info):
    decode_info = b64decode(info)  # 通过base64解码成二进制bytes
    decode_info = sm2_crypt.decrypt(decode_info)
    return decode_info


def getsign(utc, uuid):
    sb = ("platform=" + platform + "&utc=" + str(utc) + "&uuid=" + str(uuid) +
          "&appsecret=" + md5key)
    m = hashlib.md5()
    m.update(sb.encode("utf-8"))
    return m.hexdigest()


def default_post(router,
                 data,
                 headers=None,
                 m_host=None,
                 isBytes=False,
                 gen_sign=True):
    if m_host is None:
        m_host = my_host
    url = m_host + router
    if gen_sign:
        my_utc = str(int(time.time()))
    sign = getsign(my_utc, my_uuid) if gen_sign else my_sign
    if headers is None:
        headers = {
            'token': my_token,
            'isApp': 'app',
            'deviceId': my_device_id,
            'deviceName': my_device_name,
            'version': my_app_edition,
            'platform': 'android',
            'Content-Type': 'application/json; charset=utf-8',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'User-Agent': 'okhttp/3.12.0',
            'utc': my_utc,
            'uuid': my_uuid,
            'sign': sign
        }
    data_json = {
        "cipherKey": CipherKeyEncrypted,
        "content": encrypt_sm4(data, b64decode(default_key), isBytes=isBytes)
    }
    print("cipherKey:\n", CipherKeyEncrypted)
    req = requests.post(url=url, data=json.dumps(data_json),
                        headers=headers)  # data进行了加密
    try:
        print("req.text:\n", req.text)
        return decrypt_sm4(req.text, b64decode(default_key)).decode()
    except:
        return req.text


def extract_hex(data_str):

    # 去除字符串中的 'b', ' 和 \' 字符
    data_str_cleaned = data_str[2:-1].replace("\\'", "").replace("\\", "")

    # 将字符串转换为字节
    data_bytes = bytes.fromhex(data_str_cleaned.replace("\\x", ""))

    # 解码Base64编码的字节串
    decoded_data = b64decode(data_bytes)

    print(decoded_data)


def save_config(token, utc, uuid, sign):
    config = configparser.ConfigParser()
    config.read('config.ini')

    # Update User section with new values
    config['User']['token'] = token
    config['User']['utc'] = utc
    config['User']['uuid'] = uuid
    config['User']['sign'] = sign

    # Write changes back to the config file
    with open('config.ini', 'w') as configfile:
        config.write(configfile)


def test2():
    # data = json.loads(default_post("/venue/venueHomPage", ""))
    # data = json.loads(default_post("/venue/venueAppointmentInfo", "41"))
    # data = json.loads(default_post("/run/getHomeRunInfo",
    #                                ""))['data']['cralist'][0]

    cipherKey = "BPIrdg9rhV9H9BgC97jMY5WCfaWt5DySWy0ujUkwEUdW9ORDI2RpURxpKQyvXnNf2UPJvr87CNEXLWgHZM3+wdkrOlGo1wa0HqJyXrPrN+ABKwbJZsL9H1pYIv4/KC7PVV8TUGZ0RSAjZq1i9JbNVT9Lw4jkDlW6rQ=="
    content = "o0+eXBfW5EsmnAn8cvsKU91i4mZtlGHPj+1cJB41eTxsyiRub04eMWlEZ/91kaDnXmzyLPOqECM8X2XOBK8NLLVEGYNiFwpt9T0NxjmA1yk="

    req_text = "ZBDw50TId9fiE0esOZ6xAEA2lqwBQjswchu2YmGMtDc/D45fuE6BNKrwdR+CsmByZUQcKRWH3/IhNq9GLoMmjIGH6g2Wx2CakKb3MUoxDA6wYmHIb/OCxB+0qeS8JqkyijXWlKxreU80lwdrnwfdebeWRc/LE6WP42Uhypk9zTeqdnEkVzyWayQYGK9Y/OkFsGJhyG/zgsQftKnkvCapMhuaGXu/Qu9VlbjcQ+VRP/sfwGqEHIhZlP/HabhxiyFKPtyjAQuZ8PsF0v0g134Q6RCOit1tzsURnAa9by44sgdZQbq9zAIlzPBv9/VaWqru3ixZ884fqNmdNV0aL1feJu8xGJL5YXy+ogdoYJvIYYywsvd+So3/fJEA+Kd8DCHQxo83AtWaMvCkXbOMPaW6pPSWGMqo3y2gD4G9BMkKXhwJ5h60VMOtzBCRawup/5pH7F09OMSofsLJYl/q/Ix9RVfiLvG7kn+cZbDyQVDK1W0wWDtUddeiX2WITuIO25FD"

    try:
        # data = decrypt_sm4(content, b64decode(cipherKey))
        # print(bytes_to_hex(decrypted_data))
        # data = decrypted_data.decode("gbk")
        # data = decrypt_sm4(req_text, b64decode(default_key)).decode()
        data = decrypt_sm4(req_text, b64decode(default_key))
        # print(bytes_to_hex(data))  # 打印data的真实16进制值
        # print(data)
        # data = extract_hex(data)
        # print(data)
        # 尝试不同的编码方式解码
        encodings = ['utf-8', 'gbk', 'iso-8859-1', 'utf-16', 'ascii']

        for encoding in encodings:
            try:
                decoded_data = data.decode(encoding)
                print(f"Decoded using {encoding}:")
                print(decoded_data)
                break
            except UnicodeDecodeError:
                print(f"Failed to decode with {encoding}.")
    except Exception as e:
        print("解码错误，无法将数据转换为字符串:", e)


def venueHomPage():
    print(my_token)
    data = default_post("/venue/venueHomPage", "")
    return data

    # req_text = ' "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"'
    # req_text = ' "IotGF08pTDxaXVvC+HT4rr/HusjkUeycYVHKjhtd3/lYusLkVKKOmQtQrHjSbyaWb69ioy5zxnXUy80e9e5B5XgoKE/hXRpPbvfoex3sX9G9DU72o7VgGvuEFnZRNtoMXpgxofrVPV86PKPcI/dObMnyVKd16pH1Hb/5L93zoKmW3Bhw09/G6iyDa2P6wLxacr2PB2gxGS8KCUyUszlTV5Vqm7lcCpIWoP/R2CHK/eiNTtmUMakfOGGf8iHjGKUC8NbJaaTbghc5LsiLDygUNsNO3+E0Te57BM5z0NDI34WnCxoFMjXjBZFskws0dHgVGL/Ulh2Z4pluLMq+hLWIYzwqmF5swemJGzoRD1w7fHUlawX8U+oKJoZhl8dQ+if0GVqe27wKFOdGFiry1R+T1IX6rIpVvEVWAeKhancAXPlORrcMOhUfYOdLP0ydisINRZE940MNsG7hjpxE4sgeyA99ph8FWDAJBey8X1mqDgI2uI3BPJKShCFYp3aM5kvkH1YKyuO2EKj5eknjKToVS3xe7qqkDz4lwPB6SGEa2c178M/Rk9ISloTaDwde0vJZXoenLZd2wWwO9WmrazToDTQuKGlKPRJubgrKL7xTT1wMIadF10AC0kMhPk7c+i8/MqQvG6oNnaMYoNq18RE7ywOCm+ErgMR7vmE2lvi7YeKdq41IpxsfEN7lzOl5nTWM2hY3efOIjdXjOWodUOuXGCA10fD8+GpEk31NNDyIPjWd2ZrgPgucz+iu8Jy/qORVNngr2n4aeY3nsKYodpKLCacSmFtkCtXtbLoxcLGLy6Gcz+5hRgvCC/FBCvUtdbPPDOyAi4b87QDCbvWvKngVxxqN46SDKUYfu6vDaPyrPP/dTfDixrZnQCo/9yBE2kgesmVGeMa5RjLUo7ynMoOa2tQdED+Fz9JNszXV4AMHaYZ4CFMaX0oBq2xLwpy0/wAE9OyE2aTu/RMSUHtAye/25K56BJsmA5xrttdkqBDAq7Tw1slppNuCFzkuyIsPKBQ2yBcgdA8NbjM6NT5eYr5fY3OR0xq8dMtr/gbFGnIl+89cGZlIYpq9kQvNXtqKhJL0B4iLw7hevTuFA09wPHAFNNtu9URW7JBTngu7qPgHMHsR1N/861fN0V5RRrE3invJaU4VvE7RvBJAQyPpjByse+YYLdZg6fTsC4QgeFXP05NmBDdEcdvWKAID7FyhgSw04LLnq+tT88oPkBTedMWFVb6UP3ULKuM4gLpPdNVKH1Dfla2pxzSZ0LRtWFvD21x96wyEJ8MmdTq/Q/MVdqSLBt6iU9kvgBmw9hC4agQ35Hx0oS6UcGvIou2436qYK/KvV6jPExHrC1Nr02LK57pbrGCuDLWifZ3YAw4ZYnKci01+FsHGTARL1eQ0PPD4OkvPh9Wc4GardaMvNCoZdWNeFtm8iXVjouobSTUCaCRYHoTRnWx0LTSQnBpmdogdUVR38lt8q9DkiuvDBsCq6uPTJu6340ka4RTbP7le+Uftqv2vaBmZk2QukdEAcXqDqmTltnyuvkRcXrom3kuJbHT8spP2R2qRlfxPR9xMQmkQobPmCk7klcEmIQmmLCtlDbxNcr2PB2gxGS8KCUyUszlTV1dlTwaX110Sze5hQezVwMHbm/Cq9xW6Gq0iltWXW7K1/Qh/H7uX0A1fS0zDF/vuAdQUbNUT+iD1rx6S9d5zJt/Uc/npjOcDnywvrgb0OkU/pcj5fTlXh/7+eBvtAk1KLrTLXyWdXxurNYCrBCfW+vJn7Uw1T1SC02Jtz8NObsKZBGemOMcLq2gvb2IUwawQ46/7X2bi5N866e2avFht1DQXFEK8UCfpHgdgJ1QZ0DmqwiFYJnr3aIUHDoZbMMpx0AvnTCyvYgtTENsxjjI/neyKcEGXj7/SaDlqoRc0jU3jhM9cxSWS0WM0WSbv0N2kSeuzoIPqxtPaW8zS3zIW1mcMR5XVMAqHQ1ymClj0BPK6HI6CD4YkTgmO2oK2Yh33a2cyVi11vU7XA7SS/0rQbziptL4bWJUmINipqlSCef8zzR1qhpcwm6/Xd/Bu3pv6Vo/cRiQoFlO45X0ytJ+PP/cMfyXCYxyDIQysXLmkaXDAQuUExWWNuV8qy5OGmb5hE8ISk696MrnPZHKf1luCCHUYzXOELTddot2snbvhJniMsuORfBrcw0AgEyUP2NA17C4yAZTwdzAvKlcNTaOvYA4="'
    # data = decrypt_sm4(req_text, b64decode(default_key)).decode()
    # print(data)

    # # 测试密钥加解密
    # cipherKey = conf.get("Yun", "CipherKey")
    # # e_key = encrypt_sm2(cipherKey)
    # # print("e_key:\n", e_key)
    # e_key = encrypt_sm2(cipherKey)
    # print("e_key:\n", e_key)

    # print("CipherKeyEncrypted:\n", CipherKeyEncrypted)


def test():
    # 可用，查看乒羽中心
    """
    {
        'msg': '操作成功',
        'code': 200,
        'data': {
            'imgList': ['null'],
            'appointmentDateList': [{
                'val': '星期一',
                'key': '2024-09-30'
            }],
            'venueFieldList': [{
                'timeStatus': 'Y',
                'fieldTime': '12:00-13:00',
                'venueId': 41
            }, {
                'timeStatus': 'Y',
                'fieldTime': '18:00-19:00',
                'venueId': 41
            }, {
                'timeStatus': 'Y',
                'fieldTime': '19:00-20:00',
                'venueId': 41
            }, {
                'timeStatus': 'Y',
                'fieldTime': '20:00-21:00',
                'venueId': 41
            }, {
                'timeStatus': 'Y',
                'fieldTime': '21:00-22:00',
                'venueId': 41
            }],
            'venueFieldNameList': [],
            'appointmentNotice':
            '1.乒羽中心预约每个场地每个时间段只可一人预约，预约时至少携带一人进场最多同时可携带5人(共计6人)；',
            'appointmentUserName':
            '聂羽曈',
            'appointmentUserPhone':
            '',
            'venueName':
            '乒羽中心',
            'venueAppointmentTime':
            '周一、二、四 开放时间为：12:00-13：00 晚上为：18:00-21:30 周三、六、日 全天开放；',
            'venueAddr':
            '地址：屯溪路乒羽馆',
            'appointmentDate':
            '2024-09-30',
            'appointmentWeek':
            '星期一',
            'venueAdvance':
            0,
            'cgdhPhone':
            '',
            'venueDayNum':
            0,
            'venueImgList': [],
            'crsVenueInfoList': [],
            'isWeekTrueFalse':
            True
        }
    }
    """
    # data = {'id': 41}
    # j = json.loads(
    #     default_post('/venue/venueAppointmentInfo', json.dumps(data)))

    # data = {
    #     'appointmentDate': {
    #         'val': '星期一',
    #         'key': '2024-09-30'
    #     },
    #     'venueField': {
    #         'timeStatus': 'Y',
    #         'fieldTime': '21:00-22:00',
    #         'venueId': 41
    #     }
    # }
    # 预约内容 = f'''{{"venueNumber":"{site_code}","phone":"{phone}","areaNumber":"{region_code}","appointmentDate":"{date}","selVenueFieldTime":"{time_slot}"}}'''
    # '''{"venueNumber":"CG8","phone":"15111111111","areaNumber":"CD86","appointmentDate":"2024-09-15","selVenueFieldTime":"20:00-21:00"}'''
    # **{
    #     "羽毛球2号": "CD82", "羽毛球3号": "CD83", "羽毛球4号": "CD84",
    #     "羽毛球5号": "CD85", "羽毛球7号": "CD86", "羽毛球8号": "CD87",
    #     "羽毛球9号": "CD88", "羽毛球10号": "CD89",
    #     **{"乒乓球" + str(i) + "号": f"CD{i+89}" for i in range(1, 29)}
    # }
    return "112"


def submitAppointment(sub_data):
    # data = {
    #     "venueNumber": "CG8",
    #     "phone": "15142315386",
    #     "areaNumber": "CD87",
    #     "appointmentDate": "2024-10-01",
    #     "selVenueFieldTime": "20:00-21:00"
    # }
    # data = {
    #     "venueNumber": sub_data.venueNumber,
    #     "phone": sub_data.phone,
    #     "areaNumber": sub_data.areaNumber,
    #     "appointmentDate": sub_data.appointmentDate,
    #     "selVenueFieldTime": sub_data.selVenueFieldTime
    # }
    # j = json.loads(default_post('/venue/submitAppointment', json.dumps(data)))
    # print(j)
    return sub_data


def venueAppointmentInfo():
    data = {'id': 41}
    j = json.loads(
        default_post('/venue/venueAppointmentInfo', json.dumps(data)))
    return j


if __name__ == '__main__':
    # new_run()
    test()
