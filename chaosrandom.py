import secrets
import numpy as np
import hmac
import hashlib

class ChaosRandom:
    def __init__(self):
        self.safe_values = np.array([0.21, 0.399])

    def sine_tent_map(self, x, mu):
        """
        Applies the sine-tent map function to a given value.

        Parameters:
        x (float or np.ndarray): Input value(s) for the sine-tent map.
        mu (float): Parameter for the sine-tent map function.

        Returns:
        float or np.ndarray: Transformed value(s) after applying the sine-tent map.
        """
        return np.where(x < .5,
        ((4.0 - mu) / 4.0) * (np.sin(np.pi * x)) + mu / 2.0 * x,
        (4.0 - mu) / 4.0) * (np.sin(np.pi * x)) + mu / 2.0 * (1 - x)

    def generate_sequence(self, x_initial, mu, length):
        """
        Generates a sequence of values using the sine-tent map function.

        Parameters:
        x_initial (float): Initial value for the sequence.
        mu (float): Parameter for the sine-tent map function.
        length (int): Number of values to generate in the sequence.

        Returns:
        np.ndarray: Array of generated values.
        """
        x_vals = np.zeros(length)
        x_vals[0] = x_initial
        for i in range(length):
            x_vals[i] = self.sine_tent_map(x_vals[i-1], mu)
        return x_vals

    def generate_bit_sequence(self, x_initial, mu, iters =16000):
        """
        Generates a sequence of bits using the sine-tent map function.

        Parameters:
        x_initial (float): Initial value for the sequence.
        mu (float): Parameter for the sine-tent map function.
        iters (int): Number of iterations to run the sequence generation.

        Returns:
        np.ndarray: Array of bits (0 or 1).
        """
        x_vals = np.zeros(iters)
        x_vals[0] = x_initial
        for i in range(1, iters):
            x_vals[i] = self.sine_tent_map(x_vals[i-1], mu)

        bit_sequence = (x_vals % 1 >= 0.5).astype(int)
        return bit_sequence

    def bits_to_bytes(self, bit_sequence):
        """
        Converts a sequence of bits to bytes.

        Parameters:
        bit_sequence (np.ndarray): Array of bits (0 or 1).

        Returns:
        bytes: Byte representation of the bit sequence.
        """
        n = len(bit_sequence) // 8
        return bytes([int(''.join(map(str, bit_sequence[i:i + 8])), 2) for i in range(0, n * 8, 8)])

    def generate_bytes(self, x_initial, mu, num_iterations, num_bytes):
        """
        Generates a specified number of bytes using the sine-tent map function.

        Parameters:
        x_initial (float): Initial value for the sequence.
        mu (float): Parameter for the sine-tent map function.
        num_iterations (int): Number of iterations to run the sequence generation.
        num_bytes (int): Number of bytes to generate.

        Returns:
        bytes: Generated desired number of bytes.
        """
        bit_sequence = self.generate_bit_sequence(x_initial, mu, num_iterations)
        random_bytes = self.bits_to_bytes(bit_sequence[:num_bytes * 8])
        return random_bytes

    def generate_key(self, length):
        """
        Generates a cryptographic key using the sine-tent map function and HMAC.

        Parameters:
        length (int): Length of the key in bytes.

        Returns:
        str: Hexadecimal representation of the generated key.
        """
        random_seed = secrets.token_bytes(16)
        seed_int = int.from_bytes(random_seed, "big")

        offset = (seed_int % 100) / 10000.0

        x_initial = self.safe_values[0] + offset
        mu = self.safe_values[1] + offset
        num_iterations = 100000
        num_bytes = length
        random_bytes = self.generate_bytes(x_initial, mu, num_iterations=num_iterations, num_bytes=num_bytes)

        key = secrets.token_bytes(32)
        hmac_obj = hmac.new(key, random_bytes, hashlib.sha256)
        result = hmac_obj.digest()[:num_bytes]
        return result
    
    def generate_random_bits(self, num_bits):
        """
        Generates a specified number of random bits using the sine-tent map function.

        Parameters:
        num_bits (int): Number of bits to generate.

        Returns:
        np.ndarray: Array of generated bits (0 or 1).
        """
        seed = secrets.token_bytes(16)
        seed_int = int.from_bytes(seed, "big")
        offset = (seed_int % 1000) / 10000.0

        x_initial = self.safe_values[0] + offset
        mu = self.safe_values[1] + offset
        bits = self.generate_bit_sequence(x_initial, mu, num_bits)
        
        return bits
