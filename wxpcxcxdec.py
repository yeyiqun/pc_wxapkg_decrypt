#!/usr/bin/env python3
import hashlib
import struct
from Crypto.Cipher import AES

#解密pc中拷出来的微信小程序

def unpad(s): return s[0:(len(s) - s[-1])]

# AES-128-CBC解密
def aescbcDecrypt(src, key,iv):
    aes_obj = AES.new(key, AES.MODE_CBC, iv)
    decrypt_buf = aes_obj.decrypt(src)
    return unpad(decrypt_buf)

def decdata(encfile,wxid):
    outfile = 'dec_'+encfile
    with open(encfile,'rb')as file:
        data = file.read()
        l =len(data)
        if l<6:
            print('file too small')
            return -1
        if not data.startswith('V1MMWX'.encode('utf-8')):
            print('file format error')
            return -2

        dk = hashlib.pbkdf2_hmac('sha1', wxid.encode('utf-8'), 'saltiest'.encode('utf-8'), 1000,32)
        iv='the iv: 16 bytes'
        if l>1024+6:
            aesdata=data[6:1024+6]
            xordata=data[1024+6:]
        else:
            aesdata = data[6:]


        decout1=aescbcDecrypt(aesdata, dk, iv.encode('utf-8'));

        if l>1024+6:
            if len(wxid)<2:
                xorkey=0x66
            else:
                xorkey=wxid.encode('utf-8')[-2]
            ll=len(xordata)
            fmt = '%dB' % ll
            s = struct.unpack(fmt, xordata)
            decout2 = struct.pack(fmt, *(a ^ xorkey for a in s))
            poutf=open(outfile,'wb')
            poutf.write(decout1)
            poutf.write(decout2)
            poutf.close()
        else:
            poutf=open(outfile,'wb')
            poutf.write(decout1)
            poutf.close()

        print('decrypt ok,write file',outfile)
        return 0

    return 1

if __name__ == '__main__':
    print('start')
    fname='__APP__.wxapkg'
    fname='_portal_.wxapkg'
    fname='_banner_.wxapkg'
    fname='_search_.wxapkg'
    wxid='wxb036cafe2994d7d0'
    decdata(fname, wxid)

