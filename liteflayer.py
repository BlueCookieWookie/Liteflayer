import os
import time
import itertools
import string
import hashlib
import aiofiles
import binascii
import asyncio
from bit import Key
import pybloomfilter as pbf
from multiprocessing import Pool, cpu_count
from termcolor import colored
import threading

class LitecoinAddress:
    @staticmethod
    def string_to_private_key(input_string):
        hashed = hashlib.sha256(input_string.encode('utf-8')).digest()
        return hashed.hex()

    @staticmethod
    def private_key_to_public_key(private_key):
        key = Key.from_hex(private_key)
        return '04' + key.public_key.hex(), key.public_key.hex()

    @staticmethod
    def public_key_to_litecoin_address(public_key, is_compressed=True):
        ripemd160 = hashlib.new('ripemd160')
        sha256 = hashlib.sha256(binascii.unhexlify(public_key)).digest()
        ripemd160.update(sha256)
        pkh = ripemd160.digest()
        versioned_pkh = b'\x30' + pkh
        checksum = hashlib.sha256(hashlib.sha256(versioned_pkh).digest()).digest()[:4]
        binary_address = versioned_pkh + checksum

        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        value = int.from_bytes(binary_address, 'big')
        result = []
        while value > 0:
            value, remainder = divmod(value, 58)
            result.append(alphabet[remainder])
        while binary_address[:1] == b'\x00':
            result.append(alphabet[0])
            binary_address = binary_address[1:]
        return ''.join(result[::-1])






    @staticmethod
    def strings_to_litecoin_addresses(input_strings):
        addresses = []
        for input_string in input_strings:
            private_key = LitecoinAddress.string_to_private_key(input_string)
            uncompressed_pk, compressed_pk = LitecoinAddress.private_key_to_public_key(private_key)
            uncompressed_address = LitecoinAddress.public_key_to_litecoin_address(uncompressed_pk, is_compressed=False)
            compressed_address = LitecoinAddress.public_key_to_litecoin_address(compressed_pk)
            addresses.append((uncompressed_address, compressed_address))
        return addresses





class Checker:
    DATABASE = 'addresses.txt'
    BLOOM_FILTER_FILE = 'addresses.bloom'
    HITS_FILE = 'hits.txt'

    @classmethod
    def process_chunk(cls, words_chunk, bloom_filter_file):
        try:
            bloom_filter = pbf.BloomFilter.open(bloom_filter_file)
            hits = []

            addresses = LitecoinAddress.strings_to_litecoin_addresses(words_chunk)
            for word, (uncompressed_address, compressed_address) in zip(words_chunk, addresses):
                if uncompressed_address in bloom_filter or compressed_address in bloom_filter:
                    # Secondary check against the actual file
                    if cls.address_exists_in_file(uncompressed_address) or cls.address_exists_in_file(compressed_address):
                        
                        # Fetch the private key and corresponding public keys
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
                        hits.append(hit_data)
            return hits
        except Exception as e:
            print(f"Error occurred while processing chunk: {e}")
            return []


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
        try:
            # If the Bloom filter file doesn't exist, create and populate it
            if not os.path.exists(cls.BLOOM_FILTER_FILE):
                with open(cls.DATABASE, 'r') as address_file:
                    # Count number of lines (addresses) in the file to determine Bloom filter size
                    num_addresses = sum(1 for _ in address_file)

                # Create a new Bloom filter with appropriate size and false positive rate
                bloom_filter = pbf.BloomFilter(num_addresses * 10, 0.01, cls.BLOOM_FILTER_FILE)
                
                # Populate the Bloom filter with addresses
                with open(cls.DATABASE, 'r') as address_file:
                    for address in address_file:
                        bloom_filter.add(address.strip())
            else:
                bloom_filter = pbf.BloomFilter.open(cls.BLOOM_FILTER_FILE)

            chunk_size = max(1, len(words) // cpu_count())
            words_chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]

            hit_count = 0
            with Pool(processes=cpu_count()) as pool:
                for hits in pool.starmap(cls.process_chunk, zip(words_chunks, [cls.BLOOM_FILTER_FILE] * len(words_chunks))):
                    for hit_data in hits:
                        await cls.print_hit_data(hit_data)
                        hit_count += 1
            return hit_count
        except Exception as e:
            print(f"Error occurred while checking for hits: {e}")
            return 0

    @staticmethod
    async def print_hit_data(hit_data):
        try:
            print(colored(f"\nHit found for word: '{hit_data['word']}'", "yellow"))
        
            # Deriving the uncompressed and compressed Litecoin addresses
            uncompressed_address = LitecoinAddress.public_key_to_litecoin_address(hit_data['uncompressed_public_key'], is_compressed=False)
            compressed_address = LitecoinAddress.public_key_to_litecoin_address(hit_data['compressed_public_key'])

            async with aiofiles.open(Checker.HITS_FILE, 'a') as f:
                await f.write(f"Word: {hit_data['word']} - Private Key: {hit_data['private_key']} - Uncompressed Address: {uncompressed_address} - Compressed Address: {compressed_address}\n")
        
            print(colored(f"Private Key: {hit_data['private_key']}", "magenta"))
            print(colored(f"Public Key (Uncompressed): {hit_data['uncompressed_public_key']}", "magenta"))
            print(colored(f"Uncompressed Address: {uncompressed_address}", "blue"))
            print(colored(f"Public Key (Compressed): {hit_data['compressed_public_key']}", "magenta"))
            print(colored(f"Compressed Address: {compressed_address}", "blue"))
        except Exception as e:
            print(f"Error occurred while printing hit data: {e}")







class WordlistGenerator:

    def __init__(self):
        self.batch_size = 40000
        self.current_position = 0
        self.current_word = ""
        self.is_processing = False
        self.hits = 0
        self.start_time = None

    @staticmethod
    def generate_logo(title):
        return f"""
           
            $$\       $$\   $$\                $$$$$$\  $$\                                         
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

    def collect_inputs(self):
        try:
            self.prefix = input(colored("Enter prefix for each line (leave empty for no prefix): ", "cyan"))
            self.suffix = input(colored("Enter suffix for each line (leave empty for no suffix): ", "cyan"))
            specific_chars = input(colored("Enter specific characters (leave empty for all possible letters/numbers/special characters): ", "cyan"))
            self.charset = specific_chars if specific_chars else string.ascii_letters + string.digits + "-=!@#$%^&*()_+[]\{}|;:',./?~"
            self.min_length = int(input(colored("Enter minimum number of random characters (after the prefix if any): ", "cyan")))
            self.max_length = int(input(colored("Enter maximum number of random characters (after the prefix if any): ", "cyan")))
            if self.min_length > self.max_length:
                print("Error: Minimum length cannot be greater than maximum length.")
                return False
            self.total_combinations = sum([len(self.charset)**i for i in range(self.min_length, self.max_length+1)])
            return True
        except ValueError:
            print("Error: Please provide valid numbers for lengths.")
            return False
        except Exception as e:
            print(f"An unexpected error occurred while collecting inputs: {e}")
            return False

    def generate_next_word(self):
        for length in range(self.min_length, self.max_length + 1):
            for word in itertools.product(self.charset, repeat=length):
                self.current_word = self.prefix + ''.join(word) + self.suffix
                self.current_position += 1
                yield self.current_word

    def print_progress(self):
        while self.is_processing:
            elapsed_time = time.time() - self.start_time
            wps = self.current_position / elapsed_time
            print(colored(f"\rCurrent Word: [{self.current_word}] -- Progress: ({self.current_position}/{self.total_combinations}) -- Hits: [{self.hits}] -- WPS: [{wps:.2f}]", "green"), end="")
            time.sleep(5)

    async def generate_wordlist(self, check=True):
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

    async def check_custom_wordlist(self, filename):
        with open(filename, 'r') as f:
            wordlist = f.readlines()

        self.start_time = time.time()
        self.hits = await Checker.check_for_hits(wordlist)
        self.is_processing = False





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



