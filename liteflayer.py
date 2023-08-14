import os
import time
import threading
import itertools
import string
import hashlib
import sys
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

    BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @staticmethod
    def convert_bits(data, from_bits, to_bits, pad=True):
        """Convert data from one bit format to another."""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << to_bits) - 1
        max_acc = (1 << (from_bits + to_bits - 1)) - 1
        for value in data:
            acc = ((acc << from_bits) | value) & max_acc
            bits += from_bits
            while bits >= to_bits:
                bits -= to_bits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (to_bits - bits)) & maxv)
        elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
            raise ValueError("Invalid data")
        return ret

    @staticmethod
    def bech32_polymod(values):
        """Internal function that computes the Bech32 checksum."""
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    @staticmethod
    def bech32_create_checksum(hrp, data):
        """Compute the checksum values given HRP and data."""
        values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data
        polymod = LitecoinAddress.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


    @staticmethod
    def public_key_to_litecoin_bech32(pkh):
        """Convert a public key to a Litecoin Bech32 address."""
        version = 0
        address = [version] + LitecoinAddress.convert_bits(pkh, 8, 5)
        return "ltc1" + ''.join([LitecoinAddress.BECH32_CHARS[d] for d in address + LitecoinAddress.bech32_create_checksum("ltc", address)])

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
        addresses = []
        for input_string in input_strings:
            private_key = LitecoinAddress.string_to_private_key(input_string)
            uncompressed_pk, compressed_pk = LitecoinAddress.private_key_to_public_key(private_key)
            uncompressed_address, compressed_address, bech32_address = None, None, None

            if address_choice in ["1", "3"]:
                uncompressed_address = LitecoinAddress.public_key_to_litecoin_address(uncompressed_pk, is_compressed=False)
                compressed_address = LitecoinAddress.public_key_to_litecoin_address(compressed_pk, is_compressed=True)

            if address_choice in ["2", "3"]:
                sha256_hashed = hashlib.sha256(binascii.unhexlify(compressed_pk)).digest()
                ripemd160_hashed = hashlib.new('ripemd160', sha256_hashed).digest()
                bech32_address = LitecoinAddress.public_key_to_litecoin_bech32(ripemd160_hashed)

            addresses.append((uncompressed_address, compressed_address, bech32_address))

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
        for word, (uncompressed_address, compressed_address, bech32_address) in zip(words_chunk, addresses):
            if (address_choice == "1" and (uncompressed_address in bloom_filter or compressed_address in bloom_filter)) or \
                (address_choice == "2" and bech32_address in bloom_filter) or \
                (address_choice == "3" and (uncompressed_address in bloom_filter or compressed_address in bloom_filter or bech32_address in bloom_filter)):

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
            for _, (uncompressed_address, compressed_address, bech32_address) in zip([word], addresses):
                if cls.address_exists_in_file(uncompressed_address) or cls.address_exists_in_file(compressed_address) or cls.address_exists_in_file(bech32_address):
                    private_key = LitecoinAddress.string_to_private_key(word)
                    uncompressed_public_key, compressed_public_key = LitecoinAddress.private_key_to_public_key(private_key)
                    hit_data = {
                        "word": word,
                        "private_key": private_key,
                        "uncompressed_public_key": uncompressed_public_key,
                        "compressed_public_key": compressed_public_key,
                        "uncompressed_address": uncompressed_address,
                        "compressed_address": compressed_address,
                        "bech32_address": bech32_address
                    }
                    await cls.print_hit_data(hit_data)
                    hit_count += 1
        return hit_count



    @staticmethod
    async def print_hit_data(hit_data: dict):
        """Print hit data."""
        print(colored(f"\n{'=' * 80}", "yellow"))
        print(colored(f"Hit found for word: '{hit_data['word']}'", "yellow"))
        print(colored(f"{'=' * 80}", "yellow"))
    
        uncompressed_address = LitecoinAddress.public_key_to_litecoin_address(hit_data['uncompressed_public_key'], is_compressed=False)
        compressed_address = LitecoinAddress.public_key_to_litecoin_address(hit_data['compressed_public_key'])
        bech32_address = hit_data['bech32_address']
        async with aiofiles.open(HITS_FILE, 'a') as f:
            await f.write(f"Word: {hit_data['word']} - Private Key: {hit_data['private_key']} - Uncompressed Address: {uncompressed_address} - Compressed Address: {compressed_address} - Bech32 Address: {bech32_address}\n")
        print(colored(f"Private Key                 : {hit_data['private_key']}", "magenta"))
        print(colored(f"Public Key (Uncompressed)   : {hit_data['uncompressed_public_key']}", "magenta"))
        print(colored(f"Uncompressed Address        : {uncompressed_address}", "blue"))
        print(colored(f"Public Key (Compressed)     : {hit_data['compressed_public_key']}", "magenta"))
        print(colored(f"Compressed Address          : {compressed_address}", "blue"))
        print(colored(f"Bech32 Address               : {bech32_address}", "blue"))



class WordlistGenerator:
    """Utility class for generating and processing wordlists."""

    def __init__(self):
        self.batch_size = 20000
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

    def generate_from_pattern(self, pattern: str, charset: str) -> str:
        if not pattern:
            yield ""
            return

        char = pattern[0]
        remainder = pattern[1:]

        if char == "?":
            j = 1
            while j < len(pattern) and (pattern[j].isdigit() or pattern[j] == '-'):
                j += 1

            if '-' in pattern[1:j]:
                start, end = map(int, pattern[1:j].split('-'))
                remainder = pattern[j:]
            else:
                start = 1
                if j > 1:
                    end = int(pattern[1:j])
                    remainder = pattern[j:]
                else:
                    end = 1

            for count in range(start, end + 1):
                for combo in itertools.product(charset, repeat=count):
                    for word in self.generate_from_pattern(remainder, charset):
                        yield ''.join(combo) + word

        elif pattern[:2] in ['!U', '!L', '!#', '!@']:
            j = 2
            while j < len(pattern) and (pattern[j].isdigit() or pattern[j] == '-'):
                j += 1

            if '-' in pattern[2:j]:
                start, end = map(int, pattern[2:j].split('-'))
                remainder = pattern[j:]
            else:
                raise ValueError(f"Invalid pattern for {pattern[:2]}. Expected a range format like 1-2.")

            if pattern[:2] == '!U':
                subset = string.ascii_uppercase
            elif pattern[:2] == '!L':
                subset = string.ascii_lowercase
            elif pattern[:2] == '!#':
                subset = string.digits
            elif pattern[:2] == '!@':
                subset = "-=!@#$%^&*()_+[]\{}|;:',./?~"

            for count in range(start, end + 1):
                for combo in itertools.product(subset, repeat=count):
                    for word in self.generate_from_pattern(remainder, charset):
                        yield ''.join(combo) + word

        else:
            for word in self.generate_from_pattern(remainder, charset):
                yield char + word



    def collect_inputs(self) -> bool:
        """Collect input parameters for wordlist generation."""
        print(colored("\nPattern Legend:", "green"))
        
        # Basic wildcards
        print(colored("Wildcards (Represents ALL Possible possible combinations of the category):", "cyan"))
        print(colored("!U!   - ", "yellow") + "ALL Possible uppercase letters. (A to Z)")
        print(colored("!L!   - ", "yellow") + "ALL Possible lowercase letters. (a to z)")
        print(colored("!#    - ", "yellow") + "ALL Possible digits. (0 to 9)")
        print(colored("!@!   - ", "yellow") + "ALL Possible special characters from the set: -=!@#$%^&*()_+[]\{}|;:',./?~")
        print(colored("?     - ", "yellow") + "ALL Possible characters from any of the sets above.")
        
        # Range feature
        print(colored("\nNumber Range Feature:", "cyan"))
        print(colored("!U3!  - ", "yellow") + "Generates ALL Possible combinations of three uppercase letters. (AAA to ZZZ)")
        print(colored("!L2!  - ", "yellow") + "Generates ALL Possible combinations of two lowercase letters. (aa to zz)")
        print(colored("!#4!  - ", "yellow") + "Generates ALL Possible combinations of four digits. (0000 to 9999)")
        print(colored("!@2!  - ", "yellow") + "Generates ALL Possible combinations of two special characters.")
        
        # Dynamic range
        print(colored("Example with Range:", "cyan"))
        print(colored("?1-3  - ", "yellow") + "Generates ALL Possible combinations of characters from any of the sets above, from 1 to 3 characters long (e.g., a, aa, aaa to z, zz, zzz).")
        print(colored("!U1-2! - ", "yellow") + "Generates ALL Possible combinations of 1 to 2 uppercase letters. (A to ZZ)")
        
        # Example with regular strings
        print(colored("\nIntegration with Regular Strings:", "cyan"))
        print("Patterns can be combined with regular characters for custom generation. E.g.")
        print(colored("'iLove!U!  - ", "yellow") + "Generates: 'iLoveA', 'iLoveB', ... up to 'iLoveZ'.")
        print(colored("'Pass!#2! - ", "yellow") + "Generates: 'Pass00', 'Pass01', ... up to 'Pass99'.")
        print(colored("'abc?1-3' - ", "yellow") + "Generates: 'abc?', 'abc??', ... up to 'abc??? - ALL Possible possible combinations for 3 character spaces'.")
        
        print("\n")
    
        self.charset = string.ascii_letters + string.digits + "-=!@#$%^&*()_+[]\{}|;:',./?~"
    
        self.pattern = input(colored("Enter your word pattern: ", "cyan"))

        # Compute total_combinations using the generator
        self.total_combinations = self.estimate_total_combinations(self.pattern)


        return True

    def estimate_total_combinations(self, pattern: str) -> int:
        """Estimate the total combinations based on the pattern."""
        charset_size = len(self.charset)
        total = 1  # for the base case

        i = 0
        while i < len(pattern):
            char = pattern[i]
            if char == '?':
                j = i + 1
                while j < len(pattern) and (pattern[j].isdigit() or pattern[j] == '-'):
                    j += 1
                if '-' in pattern[i+1:j]:
                    start, end = map(int, pattern[i+1:j].split('-'))
                    total *= sum([charset_size**k for k in range(start, end+1)])
                    i = j
                else:
                    total *= charset_size
                    i += 1
            elif pattern[i:i+2] in ['!U', '!L', '!#', '!@']:
                j = i + 2
                while j < len(pattern) and (pattern[j].isdigit() or pattern[j] == '-'):
                    j += 1

                if '-' in pattern[i+2:j]:
                    start, end = map(int, pattern[i+2:j].split('-'))
                    if pattern[i:i+2] == '!U':
                        subset_size = 26  # Uppercase letters
                    elif pattern[i:i+2] == '!L':
                        subset_size = 26  # Lowercase letters
                    elif pattern[i:i+2] == '!#':
                        subset_size = 10  # Digits
                    elif pattern[i:i+2] == '!@':
                        subset_size = 28  # Special characters
                    total *= sum([subset_size**k for k in range(start, end+1)])
                    i = j
                else:
                    raise ValueError(f"Invalid pattern for {pattern[i:i+2]}. Expected a range format like 1-2.")
            else:
                i += 1

        return total

    def generate_next_word(self):
        """Generate the next word based on the pattern."""
        for word in self.generate_from_pattern(self.pattern, self.charset):
            self.current_word = word
            self.current_position += 1
            yield self.current_word


    def print_progress(self):
        """Print progress of wordlist generation."""
        while self.is_processing:
            elapsed_time = time.time() - self.start_time
            wps = self.current_position / elapsed_time
            percentage = (self.current_position / self.total_combinations) * 100
            progress_line = colored(f"\rCurrent Word: [{self.current_word}] -- Progress: ({self.current_position}/{self.total_combinations}) [{percentage:.2f}%] -- Hits: [{self.hits}] -- WPS: [{wps:.2f}]", "green")
            sys.stdout.write(progress_line)
            sys.stdout.flush()
            time.sleep(0.1)  # Adjusting sleep time to 0.1 second for more frequent updates



    async def generate_wordlist(self, check=True):
        """Generate a wordlist and optionALL Possibley check it against a database."""
        wordlist = []
        
        # Start the print_progress method as a separate thread
        self.is_processing = True
        progress_thread = threading.Thread(target=self.print_progress)
        progress_thread.start()

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

        # Stop the progress thread
        self.is_processing = False
        progress_thread.join()

    async def check_custom_wordlist(self, filename: str):
        """Check a custom wordlist against a database."""
        with open(filename, 'r') as f:
            wordlist = f.readlines()

        # Set the total_combinations attribute to the length of the wordlist
        self.total_combinations = len(wordlist)

        # Start the print_progress method as a separate thread
        self.is_processing = True
        progress_thread = threading.Thread(target=self.print_progress)
        progress_thread.start()

        # Initialize the current position
        self.current_position = 0
    
        wordlist_chunk = []
        for word in wordlist:
            wordlist_chunk.append(word.strip())  # Remove newline characters
            self.current_position += 1
            self.current_word = word.strip()

            if len(wordlist_chunk) == self.batch_size:
                self.hits += await Checker.check_for_hits(wordlist_chunk)
                wordlist_chunk = []
    
        if wordlist_chunk:
            self.hits += await Checker.check_for_hits(wordlist_chunk)

        # Stop the progress thread
        self.is_processing = False
        progress_thread.join()

        print(colored(f"\n{'*' * 40}", "yellow"))
        print(colored(f"Done!", "cyan"))
        print(colored(f"Hits: {self.hits}/{self.total_combinations}.", "green"))
        print(colored(f"{'*' * 40}", "yellow"))


    def reset(self):
        """Reset the state of the generator."""
        self.current_position = 0
        self.current_word = ""
        self.is_processing = False
        self.hits = 0
        self.start_time = None

    def estimate_file_size(self, pattern: str, charset: str) -> str:
        """Estimate the file size based on the pattern."""
        charset_size = len(charset)
        total_combinations = 1  # for the base case
        avg_length = 0

        i = 0
        while i < len(pattern):
            char = pattern[i]
            if char == '?':
                j = i + 1
                while j < len(pattern) and (pattern[j].isdigit() or pattern[j] == '-'):
                    j += 1
                if '-' in pattern[i+1:j]:
                    start, end = map(int, pattern[i+1:j].split('-'))
                    avg_length += (start + end) / 2
                    total_combinations *= sum([charset_size**k for k in range(start, end+1)])
                    i = j
                else:
                    avg_length += 1
                    total_combinations *= charset_size
                    i += 1
            elif char in ['!U', '!L', '!#', '!@']:
                count = 1
                if i+2 < len(pattern) and pattern[i+2].isdigit():
                    count = int(pattern[i+2])
                    i += 3
                else:
                    i += 2
                avg_length += count
                total_combinations *= count
            else:
                avg_length += 1
                i += 1

        size_bytes = total_combinations * (avg_length + 1)  # +1 for the newline character

        # Convert to human-readable format
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0



if __name__ == '__main__':
    generator = WordlistGenerator()
    print(colored(generator.generate_logo(""), "green"))

    print(colored("Select the type of addresses to generate and check for:", "cyan"))
    print(colored("1. P2PKH Only", "yellow"))
    print(colored("2. Bech32 Only", "yellow"))
    print(colored("3. BOTH P2PKH and Bech32", "yellow"))

    address_choice = input(colored("Choose an address type (1/2/3): ", "cyan"))
    if address_choice not in ["1", "2", "3"]:
        print("Invalid choice. Exiting.")
        sys.exit()


    while True:
        print(colored("1. Generate & Check Wordlist", "cyan"))
        print(colored("2. Generate Wordlist Only & Save To File", "cyan"))
        print(colored("3. Check Custom Wordlist", "cyan"))
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
            # Clear the wordlist file
            open("wordlist.txt", "w").close()
            success = generator.collect_inputs()
            if not success:
                continue

            # Estimate the total number of words in the wordlist
            total_words = generator.estimate_total_combinations(generator.pattern)
            print(colored(f"\nEstimated total number of words: {total_words}", "yellow"))

            estimated_size = generator.estimate_file_size(generator.pattern, generator.charset)
            print(colored(f"Estimated file size: {estimated_size}.", "yellow"))
            proceed = input("Do you want to proceed? (Y/N): ").strip().lower()
            if proceed != 'y':
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
