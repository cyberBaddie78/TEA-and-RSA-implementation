#!/usr/bin/env python3
"""
TEA Encryption Tool
All-in-one file containing TEA (Tiny Encryption Algorithm) encryption and interactive command-line interface.

Features:
- TEA (Tiny Encryption Algorithm) encryption
- PBKDF2 with SHA-256 for password-based key generation
- Interactive command-line interface for encryption/decryption
- Base64 encoded output for easy sharing
- Support for multiline text input
- File encryption and decryption support
- Error handling and validation
"""

import base64
import os
import getpass
import struct
import hashlib


class TEACrypto:
    """
    TEA (Tiny Encryption Algorithm) encryption/decryption class.
    TEA is a simple block cipher that operates on 64-bit blocks with a 128-bit key.
    """
    
    def __init__(self):
        self.key_length = 16  # 128 bits
        self.block_size = 8   # 64 bits
        self.delta = 0x9E3779B9
        self.rounds = 32
        self.salt_length = 16  # 128 bits
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a cryptographic key from a password using PBKDF2.
        
        Args:
            password (str): The password to derive the key from
            salt (bytes): Salt for key derivation
            
        Returns:
            bytes: Derived key (128 bits)
        """
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # iterations
            dklen=self.key_length
        )
    
    def _tea_encrypt_block(self, v: list, k: list) -> list:
        """
        Encrypt a single 64-bit block using TEA.
        
        Args:
            v (list): Two 32-bit integers representing the block [v0, v1]
            k (list): Four 32-bit integers representing the key [k0, k1, k2, k3]
            
        Returns:
            list: Encrypted block [v0, v1]
        """
        v0, v1 = v[0], v[1]
        sum_val = 0
        
        for _ in range(self.rounds):
            sum_val = (sum_val + self.delta) & 0xFFFFFFFF
            v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
            v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum_val) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        
        return [v0, v1]
    
    def _tea_decrypt_block(self, v: list, k: list) -> list:
        """
        Decrypt a single 64-bit block using TEA.
        
        Args:
            v (list): Two 32-bit integers representing the encrypted block [v0, v1]
            k (list): Four 32-bit integers representing the key [k0, k1, k2, k3]
            
        Returns:
            list: Decrypted block [v0, v1]
        """
        v0, v1 = v[0], v[1]
        sum_val = (self.delta * self.rounds) & 0xFFFFFFFF
        
        for _ in range(self.rounds):
            v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_val) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
            sum_val = (sum_val - self.delta) & 0xFFFFFFFF
        
        return [v0, v1]
    
    def _pad_data(self, data: bytes) -> bytes:
        """
        Add PKCS7 padding to data.
        
        Args:
            data (bytes): Data to pad
            
        Returns:
            bytes: Padded data
        """
        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        
        Args:
            data (bytes): Padded data
            
        Returns:
            bytes: Unpadded data
        """
        padding_length = data[-1]
        return data[:-padding_length]
    
    def encrypt(self, plaintext: str, password: str) -> str:
        """
        Encrypt plaintext using TEA.
        
        Args:
            plaintext (str): Text to encrypt
            password (str): Password for key derivation
            
        Returns:
            str: Base64 encoded encrypted data with salt
        """
        # Generate salt and derive key
        salt = os.urandom(self.salt_length)
        key_bytes = self._derive_key(password, salt)
        
        # Convert key to four 32-bit integers
        key = list(struct.unpack('>4I', key_bytes))
        
        # Convert plaintext to bytes and pad
        plaintext_bytes = plaintext.encode('utf-8')
        padded_data = self._pad_data(plaintext_bytes)
        
        # Encrypt each 64-bit block
        encrypted_blocks = []
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            v = list(struct.unpack('>2I', block))
            encrypted_block = self._tea_encrypt_block(v, key)
            encrypted_blocks.extend(encrypted_block)
        
        # Pack encrypted blocks into bytes
        encrypted_data = struct.pack(f'>{len(encrypted_blocks)}I', *encrypted_blocks)
        
        # Combine salt + encrypted data
        result = salt + encrypted_data
        
        # Return base64 encoded result
        return base64.b64encode(result).decode('utf-8')
    
    def decrypt(self, encrypted_b64: str, password: str) -> str:
        """
        Decrypt TEA encrypted data.
        
        Args:
            encrypted_b64 (str): Base64 encoded encrypted data
            password (str): Password used for encryption
            
        Returns:
            str: Decrypted plaintext
        """
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_b64.encode('utf-8'))
            
            # Extract salt and ciphertext
            salt = encrypted_data[:self.salt_length]
            ciphertext = encrypted_data[self.salt_length:]
            
            # Derive the same key using the same password and salt
            key_bytes = self._derive_key(password, salt)
            key = list(struct.unpack('>4I', key_bytes))
            
            # Decrypt each 64-bit block
            num_integers = len(ciphertext) // 4
            encrypted_blocks = list(struct.unpack(f'>{num_integers}I', ciphertext))
            
            decrypted_blocks = []
            for i in range(0, len(encrypted_blocks), 2):
                v = encrypted_blocks[i:i + 2]
                decrypted_block = self._tea_decrypt_block(v, key)
                decrypted_blocks.extend(decrypted_block)
            
            # Pack decrypted blocks into bytes
            decrypted_data = struct.pack(f'>{len(decrypted_blocks)}I', *decrypted_blocks)
            
            # Remove padding
            unpadded_data = self._unpad_data(decrypted_data)
            
            return unpadded_data.decode('utf-8')
            
        except Exception as e:
            raise ValueError("Decryption failed. Wrong password or corrupted data.") from e
    
    def encrypt_file(self, input_path: str, output_path: str, password: str):
        """
        Encrypt a text file.
        
        Args:
            input_path (str): Path to the input file
            output_path (str): Path to save encrypted file
            password (str): Password for encryption
        """
        try:
            # Read the file content
            with open(input_path, 'r', encoding='utf-8') as f:
                plaintext = f.read()
            
            # Encrypt the content
            encrypted = self.encrypt(plaintext, password)
            
            # Write encrypted content to output file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(encrypted)
                
            return True
        except Exception as e:
            raise Exception(f"File encryption failed: {e}")
    
    def decrypt_file(self, input_path: str, output_path: str, password: str):
        """
        Decrypt a text file.
        
        Args:
            input_path (str): Path to the encrypted file
            output_path (str): Path to save decrypted file
            password (str): Password for decryption
        """
        try:
            # Read the encrypted file content
            with open(input_path, 'r', encoding='utf-8') as f:
                encrypted_text = f.read()
            
            # Decrypt the content
            decrypted = self.decrypt(encrypted_text, password)
            
            # Write decrypted content to output file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(decrypted)
                
            return True
        except Exception as e:
            raise Exception(f"File decryption failed: {e}")


class InteractiveTEA:
    """Interactive TEA Encryption Tool"""
    
    def __init__(self):
        self.tea = TEACrypto()
        
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        """Print the application banner."""
        print("=" * 60)
        print("🔐 INTERACTIVE TEA ENCRYPTION TOOL 🔐")
        print("=" * 60)
        print("TEA (Tiny Encryption Algorithm) with Secure Key Derivation")
        print("=" * 60)
        
    def get_user_choice(self):
        """Get user's choice for operation."""
        print("\n📋 Choose an operation:")
        print("1. 🔒 Encrypt Text")
        print("2. 🔓 Decrypt Text")
        print("3. 📄 Encrypt File")
        print("4. 📂 Decrypt File")
        print("5. 🚪 Exit")
        print("-" * 40)
        
        while True:
            choice = input("Enter your choice (1-5): ").strip()
            if choice in ['1', '2', '3', '4', '5']:
                return choice
            else:
                print("❌ Invalid choice! Please enter 1-5.")
                
    def get_multiline_input(self, prompt):
        """Get multiline input from user."""
        print(prompt)
        print("(Press Enter twice or Ctrl+D when finished)")
        lines = []
        try:
            while True:
                line = input()
                if line == '' and lines and lines[-1] == '':
                    break
                lines.append(line)
            # Remove the last empty line if it exists
            if lines and lines[-1] == '':
                lines.pop()
        except EOFError:
            pass
        
        return '\n'.join(lines)
        
    def encrypt_text(self):
        """Handle text encryption."""
        print("\n🔒 ENCRYPT TEXT")
        print("-" * 40)
        
        # Get password
        password = getpass.getpass("Enter password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        # Get plaintext
        plaintext = self.get_multiline_input("Enter text to encrypt:")
        if not plaintext:
            print("❌ No text provided!")
            return
        
        try:
            # Encrypt using the TEA instance
            encrypted = self.tea.encrypt(plaintext, password)
            
            print("\n✅ ENCRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"📏 Original text length: {len(plaintext)} characters")
            print(f"🔐 Encrypted length: {len(encrypted)} characters")
            print("\n📝 ENCRYPTED TEXT (Base64):")
            print("-" * 30)
            print(encrypted)
            print("-" * 30)
            
            # Ask if user wants to copy or save
            print("\n💡 You can now:")
            print("- Copy the encrypted text above")
            print("- Save it to a file")
            print("- Share it securely")
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            
    def decrypt_text(self):
        """Handle text decryption."""
        print("\n🔓 DECRYPT TEXT")
        print("-" * 40)
        
        # Get password
        password = getpass.getpass("Enter password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        # Get encrypted text
        encrypted_text = self.get_multiline_input("Enter encrypted text (Base64):")
        if not encrypted_text:
            print("❌ No encrypted text provided!")
            return
        
        try:
            # Decrypt using the TEA instance
            decrypted = self.tea.decrypt(encrypted_text, password)
            
            print("\n✅ DECRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"🔐 Encrypted text length: {len(encrypted_text)} characters")
            print(f"📄 Decrypted text length: {len(decrypted)} characters")
            print("\n📄 DECRYPTED TEXT:")
            print("-" * 30)
            print(decrypted)
            print("-" * 30)
            
        except ValueError as e:
            print(f"❌ Decryption failed: {e}")
            print("💡 Possible reasons:")
            print("   • Wrong password")
            print("   • Corrupted or invalid encrypted data")
        except Exception as e:
            print(f"❌ Decryption error: {e}")

    def encrypt_file(self):
        """Handle file encryption."""
        print("\n📄 ENCRYPT FILE")
        print("-" * 40)
        
        # Get input file path
        input_path = input("Enter input file path: ").strip()
        if not input_path:
            print("❌ File path cannot be empty!")
            return
        
        if not os.path.exists(input_path):
            print(f"❌ File not found: {input_path}")
            return
        
        # Get output file path
        default_output = input_path + ".encrypted"
        output_path = input(f"Enter output file path (default: {default_output}): ").strip()
        if not output_path:
            output_path = default_output
        
        # Get password
        password = getpass.getpass("Enter password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        try:
            # Get file size
            file_size = os.path.getsize(input_path)
            
            print(f"\n⏳ Encrypting file ({file_size} bytes)...")
            self.tea.encrypt_file(input_path, output_path, password)
            
            print("\n✅ FILE ENCRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"📁 Input file: {input_path}")
            print(f"🔐 Output file: {output_path}")
            print(f"📏 Original size: {file_size} bytes")
            print(f"🔐 Encrypted size: {os.path.getsize(output_path)} bytes")
            
        except Exception as e:
            print(f"❌ File encryption failed: {e}")

    def decrypt_file(self):
        """Handle file decryption."""
        print("\n📂 DECRYPT FILE")
        print("-" * 40)
        
        # Get input file path
        input_path = input("Enter encrypted file path: ").strip()
        if not input_path:
            print("❌ File path cannot be empty!")
            return
        
        if not os.path.exists(input_path):
            print(f"❌ File not found: {input_path}")
            return
        
        # Get output file path
        default_output = input_path.replace(".encrypted", ".decrypted")
        if default_output == input_path:
            default_output = input_path + ".decrypted"
        
        output_path = input(f"Enter output file path (default: {default_output}): ").strip()
        if not output_path:
            output_path = default_output
        
        # Get password
        password = getpass.getpass("Enter password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        try:
            # Get file size
            file_size = os.path.getsize(input_path)
            
            print(f"\n⏳ Decrypting file ({file_size} bytes)...")
            self.tea.decrypt_file(input_path, output_path, password)
            
            print("\n✅ FILE DECRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"🔐 Input file: {input_path}")
            print(f"📁 Output file: {output_path}")
            print(f"🔐 Encrypted size: {file_size} bytes")
            print(f"📏 Decrypted size: {os.path.getsize(output_path)} bytes")
            
        except ValueError as e:
            print(f"❌ Decryption failed: {e}")
            print("💡 Possible reasons:")
            print("   • Wrong password")
            print("   • Corrupted or invalid encrypted data")
        except Exception as e:
            print(f"❌ File decryption failed: {e}")
            
    def show_help(self):
        """Show help information."""
        print("\n📖 HELP")
        print("=" * 60)
        print("""
📝 HOW TO USE THIS TOOL:

1. ENCRYPT TEXT (Option 1):
   • Enter a secure password
   • Type or paste your plaintext
   • Get your encrypted text (Base64 format)
   • Save or share the encrypted text

2. DECRYPT TEXT (Option 2):
   • Enter the same password used for encryption
   • Paste the encrypted text (Base64)
   • Get your original plaintext back

3. ENCRYPT FILE (Option 3):
   • Provide the path to your text file
   • Choose output location (or use default)
   • Enter a secure password
   • Get encrypted file

4. DECRYPT FILE (Option 4):
   • Provide the path to your encrypted file
   • Choose output location (or use default)
   • Enter the password used for encryption
   • Get decrypted file

🔒 SECURITY FEATURES:
• TEA (Tiny Encryption Algorithm) - 128-bit key, 64-bit blocks
• PBKDF2 key derivation (100,000 iterations)
• Random salt for each encryption
• PKCS7 padding for block alignment

💡 TIPS:
• Use strong passwords (8+ characters recommended)
• Don't lose your password - data cannot be recovered
• Keep your encrypted data and passwords separate
• Test with small messages/files first

⚠️  IMPORTANT:
• If you forget your password, your data cannot be recovered
• This tool provides encryption but you are responsible for password security
• Always test encryption/decryption with test data first
• TEA is a lightweight algorithm - for maximum security consider AES-256
        """)
        input("\nPress Enter to continue...")
        
    def run(self):
        """Main application loop."""
        self.clear_screen()
        self.print_banner()
        
        print("Welcome! This tool provides TEA encryption and decryption.")
        print("Choose an operation to get started.\n")
        
        while True:
            try:
                choice = self.get_user_choice()
                
                if choice == '1':
                    self.encrypt_text()
                elif choice == '2':
                    self.decrypt_text()
                elif choice == '3':
                    self.encrypt_file()
                elif choice == '4':
                    self.decrypt_file()
                elif choice == '5':
                    print("\n👋 Thank you for using TEA Encryption Tool!")
                    print("🔒 Stay secure!")
                    break
                
                # Pause before next operation
                if choice in ['1', '2', '3', '4']:
                    input("\nPress Enter to continue...")
                    self.clear_screen()
                    self.print_banner()
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ An error occurred: {e}")
                input("Press Enter to continue...")


def demo_tea():
    """Demonstration of TEA encryption/decryption."""
    print("=== TEA Encryption Demo ===")
    
    # Create TEA instance
    tea = TEACrypto()
    
    # Example usage
    password = "my_secure_password_123"
    plaintext = "This is a secret message that will be encrypted!"
    
    print(f"Original text: {plaintext}")
    print(f"Password: {password}")
    print()
    
    # Encrypt
    encrypted = tea.encrypt(plaintext, password)
    print(f"Encrypted (base64): {encrypted}")
    print()
    
    # Decrypt
    try:
        decrypted = tea.decrypt(encrypted, password)
        print(f"Decrypted: {decrypted}")
        print()
        
        # Test with wrong password
        try:
            wrong_decrypt = tea.decrypt(encrypted, "wrong_password")
        except ValueError as e:
            print(f"Expected error with wrong password: {e}")
            
    except Exception as e:
        print(f"Decryption error: {e}")


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        # Run demonstration
        demo_tea()
    else:
        # Run interactive tool
        tool = InteractiveTEA()
        tool.run()


if __name__ == "__main__":
    main()
