import time
import rsa
import caesar
import aes
import pbe
import DES
import md5
import RC4
import A5
costdic={}
while 1:
    print('Welcome to mutiencrypt! by 16020610025 Caoyinfeng\n')
    print('Please choose encryption:')
    print('1 RSA\n2 caesar\n3 AES CBC\n4 PBE\n5 DES\n6 MD5\n7 RC4\n8 A5\n')
    choose=int(raw_input())
    if choose==1:
        print('--------------------------rsa--------------------------\n')
        choose_again = raw_input('Do you want to generate new public and private keys? (y or n)\n')
        if (choose_again == 'y'):
            rsa.chooseKeys()

        instruction = raw_input('Would you like to encrypt or decrypt? (Enter e or d): \n')
        if (instruction == 'e'):
            message = raw_input('What would you like to encrypt?\n')
            option = raw_input('Do you want to encrypt using your own public key? (y or n) \n')

            if (option == 'y'):
                start = time.clock()
                print(rsa.encrypt(message))
                end = time.clock()
            else:
                file_option = raw_input('Enter the file name that stores the public key: \n')
                print(rsa.encrypt(message, file_option))

        elif (instruction == 'd'):
            message = raw_input('What would you like to decrypt?\n')
            print('Decryption...')
            print(rsa.decrypt(message))
        else:
            print('That is not a proper instruction.')
        print('--------------------------rsa end--------------------------\n')
        
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
        

    elif choose==2:
        
        print('--------------------------caesar--------------------------\n')
        encryption_key=int(raw_input('What is your encryption key?\n'))
        message=raw_input('What would you like to encrypt?\n')
        start = time.clock()
        cipher=caesar.caesar(message,encryption_key)
        end = time.clock()
        print('ciphertext is '+cipher+"\n")
        print('--------------------------caesar end--------------------------\n')
        
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
    elif choose==3:
        
        print('--------------------------AES CBC--------------------------\n') 
        moo = aes.AESModeOfOperation()
        cleartext = raw_input('What would you like to encrypt?\n')
        start = time.clock()
        cypherkey = [143,194,34,208,145,203,230,143,177,246,97,206,145,92,255,84]
        iv = [103,35,148,239,76,213,47,118,255,222,123,176,106,134,98,92]
        mode, orig_len, ciph = moo.encrypt(cleartext, moo.modeOfOperation["CBC"],
                cypherkey, moo.aes.keySize["SIZE_128"], iv)
        print 'm=%s, ol=%s (%s), ciph=%s' % (mode, orig_len, len(cleartext), ciph)
        end = time.clock()
        decr = moo.decrypt(ciph, orig_len, mode, cypherkey,
                moo.aes.keySize["SIZE_128"], iv)
        print decr
        aes.testStr(cleartext, 16, "CBC")
        print('--------------------------AES CBC end--------------------------\n')
        
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start   
    elif choose==4:  
        
        print('--------------------------PBE--------------------------\n')   
        msg = raw_input('What would you like to encrypt?\n')
        passwd = raw_input('What is your encryption key?\n')
        start = time.clock()
        s = pbe.encrypt(msg, passwd)
        end = time.clock()
        print (s)
        print (pbe.decrypt(s, passwd))
        print('--------------------------PBE end--------------------------\n')
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
    elif choose==5:
        
        print('--------------------------DES--------------------------\n')  
        key = raw_input('What is your encryption key?\n')
        text= raw_input('What would you like to encrypt?\n')
        #
        start = time.clock()
        d = DES.des()
        r = d.encrypt(key,text)
        end = time.clock()
        r2 = d.decrypt(key,r)
        print("Cipher: %r" % r)
        
        print("Deciphered: ", str(r2))
        print('--------------------------DES end--------------------------\n')  
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
    elif choose==6:
        print('--------------------------MD5--------------------------\n')  

        mess = raw_input("What would you like to hash?\n")
        start = time.clock()
        md5.init_mess(mess)
        out_put = md5.hex_digest()
        print out_put
        end = time.clock()
        print('--------------------------MD5 end--------------------------\n')  
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
    elif choose==7:
        print('--------------------------RC4--------------------------\n')  
        mode = raw_input("1 Encrypt or 2 Decode \n")
        if mode == '1':
            start = time.clock()

            message = RC4.get_message()
            key = RC4.get_key()
            box = RC4.init_box(key)
            RC4.ex_encrypt(message,box,mode)
            end = time.clock()

        elif mode == '2':
            message = RC4.get_message()
            key = RC4.get_key()
            box = RC4.init_box(key)
            RC4.ex_encrypt(message, box, mode)
        print('--------------------------RC4 end--------------------------\n')
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
    elif choose==8:
        print('--------------------------A5--------------------------\n')

        choice = raw_input("1 Encrypt or 2 Decode \n")
        if choice == '1':
            message = raw_input('What would you like to encrypt?\n')
            start = time.clock()
            A5.a5_encode(message)
            end = time.clock()
        elif choice == '2':
            bin_message = raw_input('What would you like to encrypt?\n')
            A5.a5_decode(bin_message)
        print('--------------------------A5--------------------------\n')
        print ('Cost '+str(end-start)+'s\n')
        costdic[choose]=end-start
    reslist = sorted(costdic.items(), key=lambda d:d[1],reverse = True)
    print('1 RSA\n2 caesar\n3 AES CBC\n4 PBE\n5 DES\n6 MD5\n7 RC4\n8 A5\n')
    print(reslist)

        

    


        

        


