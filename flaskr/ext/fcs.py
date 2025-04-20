import numpy as np, hashlib

from reedsolo import RSCodec, ReedSolomonError

class Commitment:
    def __init__(self, helper_data, hashed_codeword, ecc):
        self.helper_data = helper_data
        self.hashed_codeword = hashed_codeword
        self.ecc = ecc

class FCS:
    def __init__(self, biometric_template:np.ndarray, maximum_fix:int=96) -> None:
        """"""
        self.__EMBEDDING_SIZE = len(biometric_template)
        self.__maximum_fix = maximum_fix
        q_b_template = self.__quantize_embedding(biometric_template) # Convert embedding to discrete value
        codeword = self.__generate_codeword(size=self.__EMBEDDING_SIZE) # Same size as embedding (biometric template)

        self.__helper_data = np.bitwise_xor(q_b_template, codeword) # Bind biometric template with generated codeword
        self.__hashed_codeword = hashlib.sha256(bytearray(np.packbits(codeword))) # Store hashed codeword

        rsc = RSCodec(maximum_fix)
        codeword_ecc = rsc.encode(bytearray(np.packbits(codeword)))
        self.__ecc = codeword_ecc[self.__EMBEDDING_SIZE//8:]
        self.__commitment = Commitment(
            helper_data=self.__helper_data,
            hashed_codeword=self.__hashed_codeword,
            ecc=self.__ecc
        )
    
    def get_commitment(self) -> Commitment:
        return self.__commitment
    
    def __quantize_embedding(self, embedding, threshold=0.5) -> np.ndarray:
        return np.array(embedding > threshold, dtype=np.uint8)
    
    def __generate_codeword(self, size=512) -> np.ndarray:
        return np.random.randint(0, 2, size=size, dtype=np.uint8)
    
    def verify(self, probe_b_template:np.ndarray):
        probe_template = self.__quantize_embedding(probe_b_template)
        probe_codeword = np.bitwise_xor(probe_template, self.__commitment.helper_data)
        probe_codeword = bytearray(np.packbits(probe_codeword))

        rsc = RSCodec(self.__maximum_fix)
        try:
            probe_codeword_ecc = probe_codeword + self.__commitment.ecc
            decode_result = rsc.decode(probe_codeword_ecc)
            decode_result = decode_result[0] if isinstance(decode_result, tuple) else decode_result
            
            repaired_codeword = np.frombuffer(decode_result, dtype=np.uint8)
            hashed_probe_c = hashlib.sha256(bytearray(repaired_codeword))
            if hashed_probe_c.hexdigest() == self.__commitment.hashed_codeword.hexdigest():
                print("Codeword matched, Authentication True ✅")
                return True
        except ReedSolomonError:
            print("Codeword not matched, Authentication False ❌")
            return False
        print("Codeword not matched, Authentication False ❌")
        return False