# Liteflayer - A Fast Litecoin Brainwallet Cracker Written In Python

## Overview:

Liteflayer is a tool inspired by Brainflayer but designed with a built-in wordlist/phrase generator to streamline generated wordlists based on intricate patterns and subsequently converting each line into private keys, public keys, and addresses and then checks them against a database of Litecoin addresses to find a match. Unlike traditional wordlist generators, this tool integrates a distinctive wildcard pattern system with a position range feature. This ability provides users with an easier experience due to the streamlining of words directly into the checker.

> ***Performance: This tool will usually do 100k+ checks per second on modern hardware.***

> I have not had luck getting this to run on Windows unfortunately but you can just use WSL2 anyways.

**REMINDER: Later on, if you ever modify your addresses.txt file, make sure to delete the addresses.bloom file before running the program again or else it wont recognize the changes!**



## Features:

1. **Custom Wordlist Generation**: The core feature of this tool, it allows users to define patterns and produce wordlists tailored to their requirements.
2. **Wildcard Patterns with Position Ranges**: An advanced system to define patterns, allowing users to specify not just character types, but also the number of characters.
3. **Efficient Checking Mechanism**: Using a mix of custom made functions, as well as the 'Bit', 'hashlib' library, the tool efficiently validates the generated wordlists allowing you to check against 1000000 GB of words without having to actually store those words on your computer.
4. **Real-Time Progress Display**: Users are kept informed with an intuitive progress bar, showing the current word, overall progress, hits, and words per second.

## Detailed Explanation of the Wildcard Pattern System:

### Basic Wildcards:

These symbols represent broad categories of characters:

- `!U!`: Represents uppercase letters, spanning A to Z.
- `!L!`: Represents lowercase letters, spanning a to z.
- `!#`: Represents numeric digits, spanning 0 to 9.
- `!@!`: Represents special characters from the set: -=!@#$%^&*()_+[]\{}|;:',./?~
- `?`: A universal wildcard that represents characters from any of the sets mentioned above.

### Number Range Feature:

A system to specify the number of characters in a combination:

- `!U3!`: This pattern would generate combinations of three uppercase letters, ranging from AAA to ZZZ.
- `!L2!`: This would generate combinations of two lowercase letters, ranging from aa to zz.
- `!#4!`: Generates combinations of four numeric digits, ranging from 0000 to 9999.
- `!@2!`: Generates combinations of two special characters from the set mentioned above.

### Dynamic Range:

This feature adds flexibility by letting you define a starting and ending range for characters:

- `?1-3`: For instance, this pattern would produce combinations ranging from a single character to three characters long, i.e., a, aa, aaa to z, zz, zzz.
- `!U1-2!`: Generates combinations of 1 to 2 uppercase letters, ranging from A to ZZ.

### Integration with Regular Strings:

The wildcard system is flexible enough to be integrated with regular strings:

- `iLove!U!`: This pattern, for instance, would generate strings like 'iLoveA', 'iLoveB', up to 'iLoveZ'.
- `Pass!#2!`: This would produce strings like 'Pass00', 'Pass01', and so on up to 'Pass99'.

## How To Use:

1. **Run the Program**: python3 liteflayer.py
2. **Choose Your Option**: Select from generating and checking a wordlist, generating a wordlist only, using a custom wordlist for checking, or exit.
3. **Define Your Pattern**: If generating a wordlist, you'll be prompted to provide a pattern. Use the wildcard system explained above to define your pattern.
4. **Let the Tool Work**: The generator will create the wordlist based on your pattern and, if chosen, check the wordlist against a database of Litecoin addresses.


