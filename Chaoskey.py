import math
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

        # Convert the values to bits (0 or 1) based on the fractional part
        bit_sequence = [int(x % 1 >= 0.5) for x in x_vals]
        return bit_sequence

    def bits_to_bytes(self, bit_sequence):
        n = len(bit_sequence) // 8
        return bytes([int(''.join(map(str, bit_sequence[i:i + 8])), 2) for i in range(0, n * 8, 8)])

    def generate_bytes(self, x_initial, mu, num_iterations, num_bytes):
        # Generate the bit sequence using the provided function
        bit_sequence = self.generate_bit_sequence(x_initial, mu, num_iterations)
        # Convert the bit sequence to bytes
        random_bytes = self.bits_to_bytes(bit_sequence[:num_bytes * 8])
        return random_bytes

    def generate_key(self, password, length):
        if isinstance(password, bytes):
            salt_from_password = hashlib.sha256(password).digest()[:16]
            hashed_password = hashlib.pbkdf2_hmac("sha256", password, salt_from_password, 100000)

        else:
            salt_from_password = hashlib.sha256(password.encode()).digest()[:16]
            hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_from_password, 100000)

        offset = int.from_bytes(hashed_password[:2], "big") / 65536.0 * 0.2 - 0.1

        x_initial = self.safe_values[0][0] + offset
        mu = self.safe_values[0][1] + offset
        num_iterations = 10000
        num_bytes = length
        random_bytes = self.generate_bytes(x_initial, mu, num_iterations=num_iterations, num_bytes=num_bytes)
        return random_bytes


    
if __name__ == "__main__":

    #example usage
    prng = PRNG()
    password = "pepE"
    key = prng.generate_key(password, 16)
    print(key, f"Key length: {len(key)}")