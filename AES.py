import sys
import os
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = [] # SBox for encryption
invSubBytesTable = [] # SBox for decryption

def gen_tables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')

    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

def gee(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)

    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, subBytesTable)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal =
                                subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

class AES():
    
    def __init__(self , keyfile:str) -> None:

        self.keysize = 256
        self.key = open(keyfile, 'r').readline().strip()
        self.key += '0' * (self.keysize//8 - len(self.key)) if len(self.key) < self.keysize//8 else self.key[:self.keysize//8]
        self.key_bv = BitVector( textstring = self.key )

        gen_tables()

        self.key_schedule = gen_key_schedule_256(self.key_bv)

    def make_state_table(self, bitvec):
        for i in range(4):
            for j in range(4):
                statearray[j][i] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
        return statearray
    
    def print_table(self, statearray):
        sub1 = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                sub1 += statearray[j][i]
        print(sub1.get_bitvector_in_hex())
        
    def subbytes(self, statearray):
        for i in range(4):
            for j in range(4):
                statearray[i][j] = BitVector(intVal=subBytesTable[statearray[i][j].intValue()], size=8)
    
    def inv_subbytes(self, statearray):
        for i in range(4):
            for j in range(4):
                statearray[i][j] = BitVector(intVal=invSubBytesTable[statearray[i][j].intValue()], size=8)
    

    def shift_rows(self, statearray):
        for i in range(1,4):
            statearray[i] = statearray[i][i:] + statearray[i][:i]
    
    def inv_shift_rows(self, statearray):
        for i in range(1,4):
            statearray[i] = statearray[i][4-i:] + statearray[i][:4-i]
    
    def mix_columns(self, statearray):
        new_state = [[0 for x in range(4)] for x in range(4)]
        two = BitVector(bitstring='00000010')
        three = BitVector(bitstring='00000011')

        for i in range(4):
            for j in range(4):
                new_state[i][j] = statearray[i][j].gf_multiply_modular(two, AES_modulus, 8) ^ statearray[(i+1)%4][j].gf_multiply_modular(three, AES_modulus, 8) ^ statearray[(i+2)%4][j] ^ statearray[(i+3)%4][j]
        return new_state
    
    def inv_mix_columns(self, statearray):
        new_state = [[0 for x in range(4)] for x in range(4)]
        e = BitVector(bitstring='00001110')
        b = BitVector(bitstring='00001011')
        d = BitVector(bitstring='00001101')
        n = BitVector(bitstring='00001001')

        for i in range(4):
            for j in range(4):
                new_state[i][j] = statearray[i][j].gf_multiply_modular(e, AES_modulus, 8) ^ statearray[(i+1)%4][j].gf_multiply_modular(b, AES_modulus, 8) ^ statearray[(i+2)%4][j].gf_multiply_modular(d, AES_modulus, 8) ^ statearray[(i+3)%4][j].gf_multiply_modular(n, AES_modulus, 8)
        return new_state
    
    def add_key(self, statearray, round):
        combo = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                combo += statearray[j][i]
        combo ^= (self.key_schedule[4*round+4] + self.key_schedule[4*round+5] + self.key_schedule[4*round+6] + self.key_schedule[4*round+7])
        return self.make_state_table(combo)
            
    def inv_add_key(self, statearray, round):
        combo = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                combo += statearray[j][i]
        combo ^= (self.key_schedule[-8 - (round*4)] + self.key_schedule[-7 - (round*4)] + self.key_schedule[-6 - (round*4)] + self.key_schedule[-5 - (round*4)])
        return self.make_state_table(combo)
        
    def encrypt(self , plaintext:str , ciphertext:str) -> None:
        bv = BitVector(filename = plaintext)
        
        statearray = [[0 for x in range(4)] for x in range(4)]

        fout = open(ciphertext, "w")

        while (bv.more_to_read):

            # Reading Block
            bitvec = bv.read_bits_from_file(128)

            # Padding Block if required
            if bitvec._getsize() > 0 and bitvec._getsize() < 128:
                bitvec.pad_from_right(128 - bitvec._getsize())

            if bitvec._getsize() > 0:
                
                # XOR-ing First 4 words
                bitvec = bitvec ^ (self.key_schedule[0] + self.key_schedule[1] + self.key_schedule[2] + self.key_schedule[3])

                # Making State Table
                statearray = self.make_state_table(bitvec)

                for round in range(14):
                    
                    # Sub bytes
                    self.subbytes(statearray)

                    # Shift rows
                    self.shift_rows(statearray)

                    # Mix Cols
                    if round != 13:
                        statearray = self.mix_columns(statearray)

                    # add key
                    statearray = self.add_key(statearray, round)
                
                retval = BitVector(size=0)
                for i in range(4):
                    for j in range(4):
                        retval += statearray[j][i]
                retval = retval.get_bitvector_in_hex()
                fout.write(retval) 
        fout.close()


    def decrypt(self , ciphertext:str , decrypted:str) -> None:

        fin = open(ciphertext, "r")
        lines = fin.readlines()[0]
        bv = BitVector(hexstring = lines)
        fin.close()

        temp_file = open('temp.bin', 'wb')
        bv.write_to_file(temp_file)
        temp_file.close()
        bv = BitVector(filename = 'temp.bin')
        os.remove("temp.bin")

        statearray = [[0 for x in range(4)] for x in range(4)]

        fout = open(decrypted, "w")
        while (bv.more_to_read):

            # Reading Block
            bitvec = bv.read_bits_from_file(128)

            # Padding Block if required
            if bitvec._getsize() > 0 and bitvec._getsize() < 128:
                bitvec.pad_from_right(128 - bitvec._getsize())

            if bitvec._getsize() > 0:
                
                # XOR-ing First 4 words
                bitvec = bitvec ^ (self.key_schedule[-4] + self.key_schedule[-3] + self.key_schedule[-2] + self.key_schedule[-1])

                # Making State Table
                statearray = self.make_state_table(bitvec)

                for round in range(14):
                    
                    # Shift rows
                    self.inv_shift_rows(statearray)

                    # Sub bytes
                    self.inv_subbytes(statearray)

                    # add key
                    statearray = self.inv_add_key(statearray, round)

                    # Mix Cols
                    if round != 13:
                        statearray = self.inv_mix_columns(statearray)

                retval = BitVector(size=0)
                for i in range(4):
                    for j in range(4):
                        retval += statearray[j][i]
                retval = retval.get_bitvector_in_ascii()
                fout.write(retval)
        fout.close()

if __name__ == "__main__":

    cipher = AES(keyfile = sys.argv[3])

    statearray = [[0 for x in range(4)] for x in range(4)]

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command -Line Syntax")