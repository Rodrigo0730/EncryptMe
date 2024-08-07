import secrets
import math
import hmac
import hashlib

class PRNG:
    def __init__(self):
        self.safe_values = ([0.27, 3.999], [0.21, 0.399])

    def sine_tent_map(self, x, mu):
        if x < 0.5:
            return ((4 - mu) / 4) * (math.sin(math.pi * x)) + mu / 2 * x
        elif x >= 0.5:
            return ((4 - mu) / 4) * (math.sin(math.pi * x)) + mu / 2 * (1 - x)

    def generate_sequence(self, x_initial, mu, num_iterations):
        x_vals = [x_initial]
        for i in range(num_iterations):
            x_next = self.sine_tent_map(x_vals[-1], mu)
            x_vals.append(x_next)
        return x_vals

    def generate_bit_sequence(self, x_initial, mu, num_iterations=8000):
        x_vals = [x_initial]
        for i in range(num_iterations - 1):
            x_next = self.sine_tent_map(x_vals[-1], mu)
            x_vals.append(x_next)

        bit_sequence = [int(x % 1 >= 0.5) for x in x_vals]
        return bit_sequence

    def bits_to_bytes(self, bit_sequence):
        n = len(bit_sequence) // 8
        return bytes([int(''.join(map(str, bit_sequence[i:i + 8])), 2) for i in range(0, n * 8, 8)])

    def generate_bytes(self, x_initial, mu, num_iterations, num_bytes):
        bit_sequence = self.generate_bit_sequence(x_initial, mu, num_iterations)
        random_bytes = self.bits_to_bytes(bit_sequence[:num_bytes * 8])
        return random_bytes

    def generate_key(self, length):
        random_seed = secrets.token_bytes(16)
        seed_int = int.from_bytes(random_seed, "big")

        offset = (seed_int % 100) / 10000.0

        x_initial = self.safe_values[0][0] + offset
        mu = self.safe_values[0][1] + offset
        num_iterations = 100000
        num_bytes = length
        random_bytes = self.generate_bytes(x_initial, mu, num_iterations=num_iterations, num_bytes=num_bytes)

        key = secrets.token_bytes(32)
        hmac_obj = hmac.new(key, random_bytes, hashlib.sha256)
        result = hmac_obj.digest()[:num_bytes]
        return result
    
    def generate_random_bits(self, num_bits):
        #gets a truly random seed from secure pRNG python module secrets used for offset in initial conditions
        seed = secrets.token_bytes(16)
        seed_int = int.from_bytes(seed, "big")
        offset = (seed_int % 1000) / 10000.0

        x_initial = self.safe_values[0][0] + offset
        mu = self.safe_values[0][1] + offset
        bits = self.generate_bit_sequence(x_initial, mu, num_bits)
        
        return bits

if __name__ == "__main__":

    prng = PRNG()
    key = prng.generate_key(16)
    print(key, f"Length: {len(key)}")
    #generate .pi file for NIST tests
    generate_pi_file = True
    if generate_pi_file:
        num_bits = 1000000
        random_bits = prng.generate_random_bits(num_bits)
        
        with open("NIST tests results/random_bits.pi", "w") as f:
            bit_string = ""
            for bit in random_bits:
                bit_string += str(bit)

            grouped_bits = '\n'.join('   ' + bit_string[i:i + 24] for i in range(0, len(bit_string), 24))
            f.write(grouped_bits)