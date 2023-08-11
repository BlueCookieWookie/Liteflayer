import os
import time
import itertools
import string
import hashlib
import base58
import binascii
import aiofiles
import asyncio
from bit import Key
from pybloomfilter import BloomFilter
from hashlib import sha256
from pickle import dumps
from multiprocessing import Pool, cpu_count
from termcolor import colored

# Constants
DATABASE = 'addresses.txt'
BLOOM_FILTER_FILE = 'addresses.bloom'
HITS_FILE = 'hits.txt'


class LitecoinAddress:
    """Utility class for Litecoin address generation and conversions."""

    @staticmethod
    def string_to_private_key(input_string: str) -> str:
        """Convert a string to a private key using SHA256."""
        hashed = hashlib.sha256(input_string.encode('utf-8')).digest()
        return hashed.hex()

    @staticmethod
    def private_key_to_public_key(private_key: str) -> tuple:
        """Convert a private key to its uncompressed and compressed public keys."""
        key = Key.from_hex(private_key)
        uncompressed_pk = '04' + key._pk.public_key.format(compressed=False).hex()[2:]
        compressed_pk = key._pk.public_key.format(compressed=True).hex()
        return uncompressed_pk, compressed_pk

    @staticmethod
    def public_key_to_litecoin_address(public_key: str, is_compressed=True) -> str:
        """Convert a public key to a Litecoin address."""
        ripemd160 = hashlib.new('ripemd160')
        sha256 = hashlib.sha256(binascii.unhexlify(public_key)).digest()
        ripemd160.update(sha256)
        pkh = ripemd160.digest()
        versioned_pkh = b'\x30' + pkh
        checksum = hashlib.sha256(hashlib.sha256(versioned_pkh).digest()).digest()[:4]
        binary_address = versioned_pkh + checksum
        return base58.b58encode(binary_address).decode('utf-8')

    @staticmethod
    def strings_to_litecoin_addresses(input_strings: list) -> list:
        """Convert a list of strings to their corresponding Litecoin addresses."""
        addresses = []
        for input_string in input_strings:
            private_key = LitecoinAddress.string_to_private_key(input_string)
            uncompressed_pk, compressed_pk = LitecoinAddress.private_key_to_public_key(private_key)
            uncompressed_address = LitecoinAddress.public_key_to_litecoin_address(uncompressed_pk, is_compressed=False)
            compressed_address = LitecoinAddress.public_key_to_litecoin_address(compressed_pk, is_compressed=True)
            addresses.append((uncompressed_address, compressed_address))
        return addresses


def custom_hash_func(obj):
    h = sha256(dumps(obj)).digest()
    return int.from_bytes(h[:16], "big") - 2**127

class Checker:
    """Utility class for checking generated addresses against a database."""
    DATABASE = 'addresses.txt'
    BLOOM_FILTER_FILE = 'addresses.bloom'
    HITS_FILE = 'hits.txt'

    @classmethod
    def process_chunk(cls, words_chunk, bloom_filter_file):
        bloom_filter = BloomFilter.open(bloom_filter_file)
        potential_hits = []

        addresses = LitecoinAddress.strings_to_litecoin_addresses(words_chunk)
        for word, (uncompressed_address, compressed_address) in zip(words_chunk, addresses):
            if uncompressed_address in bloom_filter or compressed_address in bloom_filter:
                potential_hits.append(word)
        return potential_hits



    @staticmethod
    def address_exists_in_file(address):
        try:
            with open(Checker.DATABASE, 'r') as address_file:
                for line in address_file:
                    if address == line.strip():
                        return True
        except Exception as e:
            print(f"Error checking address in file: {e}")
            return False
        return False

    @classmethod
    async def check_for_hits(cls, words):
        # If the Bloom filter file doesn't exist, create and populate it
        if not os.path.exists(cls.BLOOM_FILTER_FILE):
            with open(cls.DATABASE, 'r') as address_file:
                # Count number of lines (addresses) in the file to determine Bloom filter size
                num_addresses = sum(1 for _ in address_file)

            # Create a new Bloom filter with appropriate size and false positive rate
            bloom_filter = BloomFilter(num_addresses * 10, 0.01, cls.BLOOM_FILTER_FILE)
            
            # Populate the Bloom filter with addresses
            with open(cls.DATABASE, 'r') as address_file:
                for address in address_file:
                    bloom_filter.add(address.strip())

        # Divide the words into chunks
        chunk_size = max(1, len(words) // cpu_count())
        words_chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]

        potential_hits = []
        with Pool(processes=cpu_count()) as pool:
            for hits in pool.starmap(cls.process_chunk, zip(words_chunks, [cls.BLOOM_FILTER_FILE] * len(words_chunks))):
                potential_hits.extend(hits)

        hit_count = 0
        for word in potential_hits:
            addresses = LitecoinAddress.strings_to_litecoin_addresses([word])
            for _, (uncompressed_address, compressed_address) in zip([word], addresses):
                if cls.address_exists_in_file(uncompressed_address) or cls.address_exists_in_file(compressed_address):
                    private_key = LitecoinAddress.string_to_private_key(word)
                    uncompressed_public_key, compressed_public_key = LitecoinAddress.private_key_to_public_key(private_key)
                    hit_data = {
                        "word": word,
                        "private_key": private_key,
                        "uncompressed_public_key": uncompressed_public_key,
                        "compressed_public_key": compressed_public_key,
                        "uncompressed_address": uncompressed_address,
                        "compressed_address": compressed_address
                    }
                    await cls.print_hit_data(hit_data)
                    hit_count += 1
        return hit_count







    @staticmethod
    async def print_hit_data(hit_data: dict):
        """Print hit data."""
        print(colored(f"\nHit found for word: '{hit_data['word']}'", "yellow"))
        uncompressed_address = LitecoinAddress.public_key_to_litecoin_address(hit_data['uncompressed_public_key'], is_compressed=False)
        compressed_address = LitecoinAddress.public_key_to_litecoin_address(hit_data['compressed_public_key'])
        async with aiofiles.open(HITS_FILE, 'a') as f:
            await f.write(f"Word: {hit_data['word']} - Private Key: {hit_data['private_key']} - Uncompressed Address: {uncompressed_address} - Compressed Address: {compressed_address}\n")
        print(colored(f"Private Key: {hit_data['private_key']}", "magenta"))
        print(colored(f"Public Key (Uncompressed): {hit_data['uncompressed_public_key']}", "magenta"))
        print(colored(f"Uncompressed Address: {uncompressed_address}", "blue"))
        print(colored(f"Public Key (Compressed): {hit_data['compressed_public_key']}", "magenta"))
        print(colored(f"Compressed Address: {compressed_address}", "blue"))



class WordlistGenerator:
    """Utility class for generating and processing wordlists."""

    def __init__(self):
        self.batch_size = 40000
        self.current_position = 0
        self.current_word = ""
        self.is_processing = False
        self.hits = 0
        self.start_time = None

    @staticmethod
    def generate_logo(title: str) -> str:
        """Generate a logo for the CLI."""
        return f"""
            $$\       $$\    $$\                $$$$$$\  $$\                                         
            $$ |      \__|  $$ |              $$  __$$\ $$ |                                        
            $$ |      $$\ $$$$$$\    $$$$$$\  $$ /  \__|$$ | $$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\  
            $$ |      $$ |\_$$  _|  $$  __$$\ $$$$\     $$ | \____$$\ $$ |  $$ |$$  __$$\ $$  __$$\ 
            $$ |      $$ |  $$ |    $$$$$$$$ |$$  _|    $$ | $$$$$$$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
            $$ |      $$ |  $$ |$$\ $$   ____|$$ |      $$ |$$  __$$ |$$ |  $$ |$$   ____|$$ |      
            $$$$$$$$\ $$ |  \$$$$  |\$$$$$$$\ $$ |      $$ |\$$$$$$$ |\$$$$$$$ |\$$$$$$$\ $$ |      
            \________|\__|   \____/  \_______|\__|      \__| \_______| \____$$ | \_______|\__|      
                                                          $$\   $$ |                    
                                                          \$$$$$$  |                    
                                                           \______/     
        {title}
        """

    @staticmethod
    def generate_from_pattern(pattern: str, charset: str) -> list:
        generated_words = [""]

        i = 0
        while i < len(pattern):
            char = pattern[i]

            if char == "?":
                generated_words = [word + c for word in generated_words for c in charset]

            elif pattern[i:i+2] == "!U":
                count = 1
                if i + 2 < len(pattern) and pattern[i+2].isdigit():
                    count = int(pattern[i+2])
                    i += 1
                uppercase = string.ascii_uppercase
                for _ in range(count):
                    generated_words = [word + c for word in generated_words for c in uppercase]
                i += 1

            elif pattern[i:i+2] == "!L":
                count = 1
                if i + 2 < len(pattern) and pattern[i+2].isdigit():
                    count = int(pattern[i+2])
                    i += 1
                lowercase = string.ascii_lowercase
                for _ in range(count):
                    generated_words = [word + c for word in generated_words for c in lowercase]
                i += 1

            elif pattern[i:i+2] == "!#":
                count = 1
                if i + 2 < len(pattern) and pattern[i+2].isdigit():
                    count = int(pattern[i+2])
                    i += 1
                numbers = string.digits
                for _ in range(count):
                    generated_words = [word + c for word in generated_words for c in numbers]
                i += 1

            elif pattern[i:i+2] == "!@":
                count = 1
                if i + 2 < len(pattern) and pattern[i+2].isdigit():
                    count = int(pattern[i+2])
                    i += 1
                special_chars = "-=!@#$%^&*()_+[]\{}|;:',./?~"
                for _ in range(count):
                    generated_words = [word + c for word in generated_words for c in special_chars]
                i += 1

            else:
                generated_words = [word + char for word in generated_words]

            i += 1

        return generated_words

    def collect_inputs(self) -> bool:
        """Collect input parameters for wordlist generation."""
        print(colored("\nPattern Legend:", "green"))
        print(colored("!U[n]! - ", "yellow") + "Represents 'n' uppercase letters. E.g. !U3! is AAA to ZZZ.")
        print(colored("!L[n]! - ", "yellow") + "Represents 'n' lowercase letters. E.g. !L2! is aa to zz.")
        print(colored("!#[n]! - ", "yellow") + "Represents 'n' numbers. E.g. !#2! is 00 to 99.")
        print(colored("!@[n]! - ", "yellow") + "Represents 'n' special characters.")
        print(colored("?   - ", "yellow") + "Represents any character from the sets above.")
        
        self.charset = string.ascii_letters + string.digits + "-=!@#$%^&*()_+[]\{}|;:',./?~"
        
        self.pattern = input(colored("Enter your word pattern: ", "cyan"))
        
        wildcards = {
            '?': len(self.charset),
            '!U': 26,  # Uppercase letters
            '!L': 26,  # Lowercase letters
            '!#': 10,  # Digits
            '!@': len("-=!@#$%^&*()_+[]\{}|;:',./?~")  # Special characters
        }

        self.total_combinations = 1
        i = 0
        while i < len(self.pattern):
            char = self.pattern[i]

            if char in wildcards:
                self.total_combinations *= wildcards[char]
                i += 1

            elif self.pattern[i:i+2] in wildcards:
                count = 1
                j = i + 2
                while j < len(self.pattern) and self.pattern[j].isdigit():
                    j += 1
                if j > i + 2:
                    count = int(self.pattern[i+2:j])
                self.total_combinations *= wildcards[self.pattern[i:i+2]]**count
                i = j

            else:
                i += 1

        return True


    def generate_next_word(self) -> str:
        """Generate the next word based on the pattern."""
        words = self.generate_from_pattern(self.pattern, self.charset)
        
        for word in words:
            self.current_word = word
            self.current_position += 1
            yield self.current_word

    def print_progress(self):
        """Print progress of wordlist generation."""
        while self.is_processing:
            elapsed_time = time.time() - self.start_time
            wps = self.current_position / elapsed_time
            print(colored(f"\rCurrent Word: [{self.current_word}] -- Progress: ({self.current_position}/{self.total_combinations}) -- Hits: [{self.hits}] -- WPS: [{wps:.2f}]", "green"), end="")
            time.sleep(5)

    async def generate_wordlist(self, check=True):
        """Generate a wordlist and optionally check it against a database."""
        wordlist = []
        for word in self.generate_next_word():
            wordlist.append(word)
            if len(wordlist) == self.batch_size:
                if check:
                    self.hits += await Checker.check_for_hits(wordlist)
                else:
                    with open("wordlist.txt", "a") as f:
                        for w in wordlist:
                            f.write(f"{w}\n")
                wordlist = []

            # Print progress every 9000 words
            if self.current_position % 9000 == 0:
                elapsed_time = time.time() - self.start_time
                wps = self.current_position / elapsed_time
                percentage = (self.current_position / self.total_combinations) * 100
                print(colored(f"\rCurrent Word: [{self.current_word}] -- Progress: ({self.current_position}/{self.total_combinations}) [{percentage:.2f}%] -- Hits: [{self.hits}] -- WPS: [{wps:.2f}]", "green"), end="")

        # Process any remaining words
        if wordlist:
            if check:
                self.hits += await Checker.check_for_hits(wordlist)
            else:
                with open("wordlist.txt", "a") as f:
                    for w in wordlist:
                        f.write(f"{w}\n")

        self.is_processing = False

    async def check_custom_wordlist(self, filename: str):
        """Check a custom wordlist against a database."""
        with open(filename, 'r') as f:
            wordlist = f.readlines()

        self.start_time = time.time()
        self.hits = await Checker.check_for_hits(wordlist)
        self.is_processing = False

    def reset(self):
        """Reset the state of the generator."""
        self.current_position = 0
        self.current_word = ""
        self.is_processing = False
        self.hits = 0
        self.start_time = None


if __name__ == '__main__':
    generator = WordlistGenerator()
    print(colored(generator.generate_logo(""), "green"))

    while True:
        print(colored("1. Generate and Check Wordlist", "cyan"))
        print(colored("2. Generate Wordlist Only", "yellow"))
        print(colored("3. Use Custom Wordlist for Checking", "blue"))
        print(colored("4. Exit", "cyan"))

        choice = input(colored("Select an option: ", "cyan"))

        if choice == "1":
            success = generator.collect_inputs()
            if not success:
                continue
            generator.start_time = time.time()
            generator.is_processing = True
            asyncio.run(generator.generate_wordlist())
            print(colored(f"\n{'*' * 40}", "yellow"))
            print(colored(f"Done!", "cyan"))
            print(colored(f"Hits: {generator.hits}/{generator.total_combinations}.", "green"))
            print(colored(f"{'*' * 40}", "yellow"))

        elif choice == "2":
            success = generator.collect_inputs()
            if not success:
                continue
            generator.start_time = time.time()
            generator.is_processing = True
            asyncio.run(generator.generate_wordlist(check=False))
            print("\nWordlist saved to wordlist.txt.")

        elif choice == "3":
            file_name = input(colored("Enter the filename of the wordlist/phrase list: ", "cyan"))
            if not os.path.exists(file_name):
                print(f"Error: The file {file_name} does not exist.")
                continue
            generator.start_time = time.time()
            generator.is_processing = True
            asyncio.run(generator.check_custom_wordlist(file_name))
            total_words = len(open(file_name).readlines())
            print(colored(f"\n{'*' * 40}", "yellow"))
            print(colored(f"Done!", "cyan"))
            print(colored(f"Hits: {generator.hits}/{total_words}.", "green"))
            print(colored(f"{'*' * 40}", "yellow"))

        elif choice == "4":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")
        generator.reset()
