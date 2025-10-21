#!/usr/bin/env python3
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib, Pango
import base64
import hashlib
import pyotp
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import re
import time

class PyTFAApp:
    def __init__(self):
        # Create main window
        self.window = Gtk.Window(title="PyTFA - 2FA Authenticator")
        self.window.set_default_size(500, 500)
        self.window.set_border_width(10)
        self.window.connect("destroy", Gtk.main_quit)
        
        # Create main box
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.window.add(self.main_box)
        
        # Create header bar
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.props.title = "PyTFA - 2FA Authenticator"
        self.window.set_titlebar(header)
        
        # Add account button
        self.add_button = Gtk.Button.new_with_label("Add Account")
        self.add_button.connect("clicked", self.on_add_account)
        header.pack_end(self.add_button)
        
        # Timer label
        self.timer_label = Gtk.Label()
        header.pack_start(self.timer_label)
        
        # Create scrolled window for accounts
        scrolled = Gtk.ScrolledWindow()
        self.main_box.pack_start(scrolled, True, True, 0)
        
        # Create list box for accounts
        self.accounts_list = Gtk.ListBox()
        self.accounts_list.set_selection_mode(Gtk.SelectionMode.NONE)
        scrolled.add(self.accounts_list)
        
        # Password entry for encryption
        self.password = None
        self.account_widgets = {}  # Store mapping of account to widgets
        
        # Load encrypted data
        self.load_encrypted_data()
        
        # Start timer to update codes
        GLib.timeout_add_seconds(1, self.update_codes)
    
    def derive_key(self, password, salt):
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_account(self, account, password):
        """Encrypt a single account"""
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(json.dumps(account).encode())
        return base64.b64encode(salt + encrypted).decode()
    
    def decrypt_account(self, encrypted_data, password):
        """Decrypt a single account"""
        try:
            data = base64.b64decode(encrypted_data.encode())
            salt, encrypted = data[:16], data[16:]
            key = self.derive_key(password, salt)
            f = Fernet(key)
            decrypted = f.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except:
            return None
    
    def load_encrypted_data(self):
        """Load encrypted data from the script itself"""
        # Read the current script
        with open(__file__, 'r') as f:
            content = f.read()
        
        # Find the encrypted data block
        match = re.search(r'# ENCRYPTED_DATA_BEGIN\n(.*?)\n# ENCRYPTED_DATA_END', content, re.DOTALL)
        if match:
            encrypted_block = match.group(1).strip()
            
            # Ask for password
            self.show_password_dialog(encrypted_block)
        else:
            # No encrypted data found, initialize empty
            self.accounts = []
            self.show_password_dialog(initial_setup=True)
    
    def save_encrypted_data(self):
        """Save encrypted data to the script itself"""
        if not self.password or not self.accounts:
            return
        
        # Encrypt each account separately
        encrypted_accounts = []
        for account in self.accounts:
            encrypted = self.encrypt_account(account, self.password)
            encrypted_accounts.append(f"# {encrypted}")
        
        encrypted_block = '# ENCRYPTED_DATA_BEGIN\n' + '\n'.join(encrypted_accounts) + '\n# ENCRYPTED_DATA_END'
        
        # Read the current script
        with open(__file__, 'r') as f:
            content = f.read()
        
        # Replace or add the encrypted data block
        pattern = r'# ENCRYPTED_DATA_BEGIN\n.*\n# ENCRYPTED_DATA_END'
        if re.search(pattern, content, re.DOTALL):
            new_content = re.sub(pattern, encrypted_block, content, flags=re.DOTALL)
        else:
            # Add the encrypted data block at the end
            new_content = content + '\n' + encrypted_block
        
        # Write back to the script
        with open(__file__, 'w') as f:
            f.write(new_content)
    
    def show_password_dialog(self, encrypted_block=None, initial_setup=False):
        """Show password entry dialog"""
        dialog = Gtk.Dialog(
            title="PyTFA Password" if not initial_setup else "Set PyTFA Password",
            parent=self.window,
            flags=0
        )
        dialog.add_buttons(
            Gtk.STOCK_OK, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL
        )
        dialog.set_default_size(300, 150)
        
        box = dialog.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        
        label = Gtk.Label(label="Enter password to decrypt your 2FA accounts:" if not initial_setup 
                         else "Set a password to encrypt your 2FA accounts:")
        box.add(label)
        
        password_entry = Gtk.Entry()
        password_entry.set_visibility(False)
        password_entry.set_placeholder_text("Password")
        box.add(password_entry)
        
        # For initial setup, add a confirmation field
        if initial_setup:
            confirm_entry = Gtk.Entry()
            confirm_entry.set_visibility(False)
            confirm_entry.set_placeholder_text("Confirm Password")
            box.add(confirm_entry)
        else:
            confirm_entry = None
        
        dialog.show_all()
        response = dialog.run()
        
        if response == Gtk.ResponseType.OK:
            password = password_entry.get_text()
            
            if initial_setup:
                confirm = confirm_entry.get_text() if confirm_entry else ""
                if password != confirm:
                    error_dialog = Gtk.MessageDialog(
                        parent=self.window,
                        flags=0,
                        message_type=Gtk.MessageType.ERROR,
                        buttons=Gtk.ButtonsType.OK,
                        text="Passwords do not match!"
                    )
                    error_dialog.run()
                    error_dialog.destroy()
                    dialog.destroy()
                    self.show_password_dialog(initial_setup=True)
                    return
                
                self.password = password
                self.accounts = []
            else:
                self.password = password
                # Try to decrypt the accounts
                self.accounts = []
                for line in encrypted_block.split('\n'):
                    line = line.strip()
                    if line.startswith('# '):
                        encrypted_data = line[2:].strip()
                        account = self.decrypt_account(encrypted_data, password)
                        if account:
                            self.accounts.append(account)
                
                if not self.accounts:
                    error_dialog = Gtk.MessageDialog(
                        parent=self.window,
                        flags=0,
                        message_type=Gtk.MessageType.ERROR,
                        buttons=Gtk.ButtonsType.OK,
                        text="Incorrect password or no accounts found!"
                    )
                    error_dialog.run()
                    error_dialog.destroy()
                    dialog.destroy()
                    self.show_password_dialog(encrypted_block)
                    return
                
                self.update_accounts_list()
        else:
            if not initial_setup:
                Gtk.main_quit()
            else:
                # Can't proceed without a password
                error_dialog = Gtk.MessageDialog(
                    parent=self.window,
                    flags=0,
                    message_type=Gtk.MessageType.ERROR,
                    buttons=Gtk.ButtonsType.OK,
                    text="Password is required!"
                )
                error_dialog.run()
                error_dialog.destroy()
                dialog.destroy()
                self.show_password_dialog(initial_setup=True)
                return
        
        dialog.destroy()
    
    def on_add_account(self, widget):
        """Handle add account button click"""
        dialog = Gtk.Dialog(
            title="Add 2FA Account",
            parent=self.window,
            flags=0
        )
        dialog.add_buttons(
            Gtk.STOCK_OK, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL
        )
        dialog.set_default_size(400, 200)
        
        box = dialog.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        
        # Service name entry
        service_label = Gtk.Label(label="Service Name:")
        service_label.set_halign(Gtk.Align.START)
        box.add(service_label)
        
        service_entry = Gtk.Entry()
        service_entry.set_placeholder_text("e.g., GitHub, Google")
        box.add(service_entry)
        
        # Secret key entry
        secret_label = Gtk.Label(label="Secret Key:")
        secret_label.set_halign(Gtk.Align.START)
        box.add(secret_label)
        
        secret_entry = Gtk.Entry()
        secret_entry.set_placeholder_text("Base32 secret key")
        box.add(secret_entry)
        
        dialog.show_all()
        response = dialog.run()
        
        if response == Gtk.ResponseType.OK:
            service = service_entry.get_text().strip()
            secret = secret_entry.get_text().strip().replace(" ", "")
            
            if service and secret:
                # Check for duplicates
                duplicate_service = any(acc['service'] == service for acc in self.accounts)
                duplicate_secret = any(acc['secret'] == secret for acc in self.accounts)
                
                if duplicate_service:
                    self.show_error_dialog("Service name already exists!")
                elif duplicate_secret:
                    self.show_error_dialog("Secret already exists for another account!")
                else:
                    # Add the account
                    account = {
                        'service': service,
                        'secret': secret
                    }
                    self.accounts.append(account)
                    self.update_accounts_list()
                    self.save_encrypted_data()
        
        dialog.destroy()
    
    def show_error_dialog(self, message):
        """Show an error dialog"""
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=message
        )
        dialog.run()
        dialog.destroy()
    
    def update_accounts_list(self):
        """Update the accounts list in the UI"""
        # Clear current list and widget mapping
        for child in self.accounts_list.get_children():
            self.accounts_list.remove(child)
        self.account_widgets = {}
        
        # Add accounts to list
        for account in self.accounts:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
            box.set_margin_top(10)
            box.set_margin_bottom(10)
            box.set_margin_start(10)
            box.set_margin_end(10)
            row.add(box)
            
            # First row: Service name and buttons
            top_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
            box.pack_start(top_box, False, False, 0)
            
            # Service label
            service_label = Gtk.Label(label=account['service'])
            service_label.set_halign(Gtk.Align.START)
            service_label.set_hexpand(True)
            top_box.pack_start(service_label, True, True, 0)
            
            # View secret button
            view_btn = Gtk.Button.new_from_icon_name("document-properties", Gtk.IconSize.BUTTON)
            view_btn.set_tooltip_text("View Secret")
            view_btn.connect("clicked", self.on_view_secret, account)
            top_box.pack_start(view_btn, False, False, 0)
            
            # Rename button
            rename_btn = Gtk.Button.new_from_icon_name("edit", Gtk.IconSize.BUTTON)
            rename_btn.set_tooltip_text("Rename Account")
            rename_btn.connect("clicked", self.on_rename_account, account)
            top_box.pack_start(rename_btn, False, False, 0)
            
            # Delete button
            delete_btn = Gtk.Button.new_from_icon_name("edit-delete", Gtk.IconSize.BUTTON)
            delete_btn.set_tooltip_text("Delete Account")
            delete_btn.connect("clicked", self.on_delete_account, account)
            top_box.pack_start(delete_btn, False, False, 0)
            
            # Second row: Code and progress bar
            bottom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            box.pack_start(bottom_box, False, False, 0)
            
            # Code label
            code_label = Gtk.Label(label="Generating...")
            code_label.set_halign(Gtk.Align.START)
            code_label.set_selectable(True)
            
            # Use monospace font for code
            font = Pango.FontDescription("Monospace 16")
            code_label.override_font(font)
            
            bottom_box.pack_start(code_label, False, False, 0)
            
            # Progress bar for timer
            progress = Gtk.ProgressBar()
            progress.set_hexpand(True)
            bottom_box.pack_start(progress, True, True, 0)
            
            self.accounts_list.add(row)
            
            # Store widget references for updating
            self.account_widgets[account['service']] = {
                'code_label': code_label,
                'progress_bar': progress
            }
        
        self.accounts_list.show_all()
    
    def on_view_secret(self, widget, account):
        """Handle view secret button click"""
        dialog = Gtk.Dialog(
            title=f"Secret for {account['service']}",
            parent=self.window,
            flags=0
        )
        dialog.add_buttons(Gtk.STOCK_OK, Gtk.ResponseType.OK)
        dialog.set_default_size(400, 100)
        
        box = dialog.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        
        # Secret label
        secret_label = Gtk.Label(label=account['secret'])
        secret_label.set_selectable(True)
        
        # Use monospace font for secret
        font = Pango.FontDescription("Monospace 12")
        secret_label.override_font(font)
        
        box.add(secret_label)
        
        dialog.show_all()
        dialog.run()
        dialog.destroy()
    
    def on_rename_account(self, widget, account):
        """Handle rename account button click"""
        dialog = Gtk.Dialog(
            title=f"Rename {account['service']}",
            parent=self.window,
            flags=0
        )
        dialog.add_buttons(
            Gtk.STOCK_OK, Gtk.ResponseType.OK,
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL
        )
        dialog.set_default_size(400, 100)
        
        box = dialog.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        
        # Service name entry
        service_label = Gtk.Label(label="New Service Name:")
        service_label.set_halign(Gtk.Align.START)
        box.add(service_label)
        
        service_entry = Gtk.Entry()
        service_entry.set_text(account['service'])
        box.add(service_entry)
        
        dialog.show_all()
        response = dialog.run()
        
        if response == Gtk.ResponseType.OK:
            new_service = service_entry.get_text().strip()
            
            if new_service and new_service != account['service']:
                # Check for duplicates
                duplicate = any(acc['service'] == new_service for acc in self.accounts if acc != account)
                
                if duplicate:
                    self.show_error_dialog("Service name already exists!")
                else:
                    # Update the account
                    account['service'] = new_service
                    self.update_accounts_list()
                    self.save_encrypted_data()
        
        dialog.destroy()
    
    def on_delete_account(self, widget, account):
        """Handle account deletion"""
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=f"Delete account for {account['service']}?"
        )
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.accounts = [acc for acc in self.accounts if acc != account]
            self.update_accounts_list()
            self.save_encrypted_data()
    
    def update_codes(self):
        """Update all TOTP codes and timer"""
        current_time = time.time()
        time_remaining = 30 - (current_time % 30)
        
        # Update global timer
        self.timer_label.set_label(f"Time remaining: {int(time_remaining)}s")
        
        for account in self.accounts:
            try:
                totp = pyotp.TOTP(account['secret'])
                code = totp.now()
                
                # Update the code label if it exists
                if account['service'] in self.account_widgets:
                    self.account_widgets[account['service']]['code_label'].set_label(code)
                    
                    # Update progress bar
                    progress = time_remaining / 30.0
                    self.account_widgets[account['service']]['progress_bar'].set_fraction(progress)
            except Exception as e:
                print(f"Error generating code for {account['service']}: {e}")
                if account['service'] in self.account_widgets:
                    self.account_widgets[account['service']]['code_label'].set_label("Invalid")
        
        return True  # Continue timeout
    
    def run(self):
        """Run the application"""
        self.window.show_all()
        Gtk.main()

# Create and run the application
if __name__ == "__main__":
    app = PyTFAApp()
    app.run()

# ENCRYPTED_DATA_BEGIN
# +rK94cKjEeXZyJxW8M1mC2dBQUFBQUJvOVdaR0ZPbTFiZ2xMWmNQZW5SYThqYzdOZG40aFpiX19kbWM4LVI2Y1BZU2FxeTZmbUxLbl9sVWRaSnpsaDVyeEg3QVBVVXZpM0ZQV1lQdHBGX3lYRGtNMHBRYzZPTWVWQnpUOGZVcktsX2tpRm1fbVg2SVBQUm1iQUlPMUk1amRsOFZFWjJFSE80VGd1SU5DTC1rUjhJV3lULWlFSUNxWmMyMXZiSXROcGpoTVh2QT0=
# bg0T/eRXkLBy3vGR1FpGZWdBQUFBQUJvOVdaRzM4M0tfcXlNb1h4YWhKZ2hnUDVzNjg4dEY4cjhTYVhidWZ0Mm9QeFhiSzdHVDZxQ3ZKWFJXWHBFVUZGakxoXzBxbG81OHEtTkZxcWpjVUh1ckJxMk16dWVUczJjV2ZGSlJRaFFsYm95TzVzTi0zV0pvdWltZ0JIdXVDV3ZzOThfdDlGMFdKR1lOcWlaaTJxOFc0aHN6aUppNjczUjRWbjdHaDIxOUg2dE5LTXNUbmQ2T1pmUU1TcXoyX0oyU2V1VUpaVmhMOVE4MVZ2VVZRaDRiS19wM1E9PQ==
# jOwyLynvaSSAWe77CG6z5mdBQUFBQUJvOVdaR09aMDNJWmx4dm1VS1NfQ21GUVdWSWg1VnBWaU5tYVFEUnFRcG1lbnBjV2x5QjMxZEhYM1otMHNsWndkX2xMdk0teE5rZmc0SkltSnMwbFpaOERnbmdOUzk5Rk9RZFVxU2dVRTlEbmVER1Fub2UwNzJobnUtM251V0JrTWdGRWs1dzY0cXZjZXAwUHJxSTRqU0Y4eVlNM3VGVkUzRjF4cWdUeWhIUmtkbngtVVdiWV9DTFlSRG1DekZBZHpNWWV4eGVVWFczOFZXckR2SnY2UWx4NkZJbXc9PQ==
# j6TEPzfw4PHMIcdFiOLL9mdBQUFBQUJvOVdaR3dMVklUdE5nRG9UUDRjVEZjQ0daMTUxTUhWbnpVazVuVVIxaENFQVZnbGlEZHNKOERmMi1iQUFMQ25XMUw2OTk5OUc2N3V0Q0Voak5VVXZCZnQ3RzFFR25MT19aX3V4OU5Hb0RCSUhDNzE4YTE4WG81RVNEU3BuaDFZNmhLeGk5QW9ZTk5DX3pUOWJuSmQ4VDlNV0x6eHp0emdPRGFxNHdRMzdvRWROV29wbVFqZVcyZ2tDd1o3X0N6b0p5OFlRckQtYjVnODFzUlBfTkV5UkN5enRVNUE9PQ==
# 5JwE6mIuU9tYyqR49r7WaGdBQUFBQUJvOVdaR2ZYRUxGY2JtYkc5dVhtdlpFYW1vT0M3dGI1OUFpMFRRd2FTQlpKT21Bd3g0V3ByNEh5SFdsWjdtSGFwV1pfTG5ucTFucW43OHZZb1FkWlE4THM5STlUOVVWMlN1a1hiWDh3Nk1zeVV1bExlYld0Rk9JRkxzaDRhV19zdDZ2Vk5INWhwcU1Ybk1SUDBLeV9FYURMRDZuekZEaUVWb1JTVmJRYnhSZXhQZDRPVWw3dHEzZVhQOXlQV19PM3Ezb21vWkR6RVl4cS1TbnF2RHFwaWROMDlyUHc9PQ==
# ENCRYPTED_DATA_END
