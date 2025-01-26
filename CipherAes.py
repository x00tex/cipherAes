from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation, IMessageEditorController
from java.util import ArrayList
from javax.swing import JMenuItem, JFrame, JPanel, JLabel, JComboBox, JTextField, JButton, JOptionPane, BorderFactory, JFileChooser
from java.awt import GridBagLayout, GridBagConstraints, Insets, BorderLayout
from java.util.concurrent import LinkedBlockingQueue
import subprocess
import threading
import array
import json
import os

class BurpExtender(IBurpExtender, IContextMenuFactory, IMessageEditorController):
    VERSION = "1.0.0"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("CipherAes")
        self._callbacks.registerContextMenuFactory(self)

        self.on_load()

        # Default settings
        self.settings = {}
        self.current_profile = "Default"
        self.default_jar_path = "encryption-util/EncryptionUtility.jar"
        self.user_jar_path = self.default_jar_path
        self.java_path = "java"

        # Load saved settings
        saved_settings = self._callbacks.loadExtensionSetting("settings")
        if saved_settings:
            self.settings = json.loads(saved_settings)
        
        # Load user-specified paths
        self.user_jar_path = self._callbacks.loadExtensionSetting("user_jar_path") or self.default_jar_path
        self.java_path = self._callbacks.loadExtensionSetting("java_path") or "java"

        # Check if the JAR file exists
        if not os.path.exists(self.user_jar_path):
            print("Encryption Utility not found at {}".format(self.user_jar_path))

        # Reference to the settings frame
        self.settings_frame = None

    def on_load(self):
        print("CipherAes, an encryption/decryption utility is loaded")
        print("Version: {}".format(self.VERSION))
        print("Author: Poorduck")
        print("GitHub: https://github.com/x00tex/CipherAes")

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Encrypt Selection", actionPerformed=lambda x: self.process_selected_text(invocation, "enc")))
        menu_list.add(JMenuItem("Decrypt Selection", actionPerformed=lambda x: self.process_selected_text(invocation, "dec")))
        menu_list.add(JMenuItem("Profiles", actionPerformed=lambda x: self.show_settings()))
        menu_list.add(JMenuItem("Settings", actionPerformed=lambda x: self.set_paths()))
        return menu_list

    def set_paths(self):
        frame = JFrame("Settings")
        frame.setLayout(GridBagLayout())
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

        panel = JPanel()
        panel.setLayout(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(5, 5, 5, 5)
        constraints.fill = GridBagConstraints.HORIZONTAL

        java_path_label = JLabel("Java Path:")
        java_path_field = JTextField(self.java_path, 20)
        java_path_button = JButton("...", actionPerformed=lambda x: self.choose_file(java_path_field))

        jar_path_label = JLabel("Encryption Utility Path:")
        jar_path_field = JTextField(self.user_jar_path, 20)
        jar_path_button = JButton("...", actionPerformed=lambda x: self.choose_file(jar_path_field))

        save_button = JButton("Save", actionPerformed=lambda x: self.save_paths(java_path_field.getText(), jar_path_field.getText(), frame))

        constraints.gridx = 0
        constraints.gridy = 0
        panel.add(java_path_label, constraints)
        constraints.gridx = 1
        panel.add(java_path_field, constraints)
        constraints.gridx = 2
        panel.add(java_path_button, constraints)

        constraints.gridx = 0
        constraints.gridy = 1
        panel.add(jar_path_label, constraints)
        constraints.gridx = 1
        panel.add(jar_path_field, constraints)
        constraints.gridx = 2
        panel.add(jar_path_button, constraints)

        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 3
        panel.add(save_button, constraints)

        frame.add(panel)
        frame.pack()
        frame.setResizable(False)
        frame.setVisible(True)

    def choose_file(self, text_field):
        file_chooser = JFileChooser()
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        return_val = file_chooser.showOpenDialog(None)
        if return_val == JFileChooser.APPROVE_OPTION:
            file = file_chooser.getSelectedFile()
            text_field.setText(file.getAbsolutePath())
    
    def save_paths(self, java_path, jar_path, frame):
        self._callbacks.saveExtensionSetting("java_path", java_path)
        self._callbacks.saveExtensionSetting("user_jar_path", jar_path)
        self.java_path = java_path  # Update instance variable
        self.user_jar_path = jar_path  # Update instance variable
        frame.dispose()
        JOptionPane.showMessageDialog(None, "Settings updated successfully!")

    def show_settings(self):
        if self.settings_frame:
            self.settings_frame.dispose()

        self.settings_frame = JFrame("Profiles")
        self.settings_frame.setLayout(GridBagLayout())
        self.settings_frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

        panel = JPanel()
        panel.setLayout(GridBagLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        constraints = GridBagConstraints()
        constraints.insets = Insets(5, 5, 5, 5)
        constraints.fill = GridBagConstraints.HORIZONTAL

        profile_label = JLabel("Profile:")
        self.profile_combo = JComboBox(self.settings.keys())
        self.profile_combo.setSelectedItem(self.current_profile)  # Set the selected item to the current profile
        self.profile_combo.addActionListener(lambda e: self.load_profile(self.profile_combo.getSelectedItem()))

        encryption_label = JLabel("Encryption:")
        encryption_options = ["AES", "DES", "DESede", "Blowfish", "RC2"]
        self.encryption_combo = JComboBox(encryption_options)

        mode_label = JLabel("Mode:")
        mode_options = ["ECB", "CBC", "CFB", "OFB", "GCM"]
        self.mode_combo = JComboBox(mode_options)

        padding_label = JLabel("Padding:")
        padding_options = ["NoPadding", "PKCS5Padding", "PKCS7Padding"]
        self.padding_combo = JComboBox(padding_options)

        format_label = JLabel("Data Format:")
        format_options = ["base64", "hex"]  # "plain" is not needed.
        self.format_combo = JComboBox(format_options)

        key_format_label = JLabel("Key Format:")
        key_format_options = ["base64", "hex", "plain"]
        self.key_format_combo = JComboBox(key_format_options)

        iv_format_label = JLabel("IV Format:")
        iv_format_options = ["base64", "hex", "plain", "N/A"]
        self.iv_format_combo = JComboBox(iv_format_options)

        key_label = JLabel("Key:")
        self.key_field = JTextField(20)

        iv_label = JLabel("IV:")
        self.iv_field = JTextField(20)

        save_button = JButton("Save", actionPerformed=lambda x: self.save_settings(self.settings_frame))
        save_button.setToolTipText("Save and activate the current profile")

        new_profile_button = JButton("New Profile", actionPerformed=lambda x: self.new_profile())
        new_profile_button.setToolTipText("Create a new profile")

        delete_profile_button = JButton("Delete Profile", actionPerformed=lambda x: self.delete_profile())
        delete_profile_button.setToolTipText("Delete the selected profile")

        reset_button = JButton("Reset", actionPerformed=lambda x: self.reset_settings())
        reset_button.setToolTipText("Reset settings and profiles to default")

        # Align components
        constraints.gridx = 0
        constraints.gridy = 0
        panel.add(profile_label, constraints)
        constraints.gridx = 1
        panel.add(self.profile_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 1
        panel.add(encryption_label, constraints)
        constraints.gridx = 1
        panel.add(self.encryption_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 2
        panel.add(mode_label, constraints)
        constraints.gridx = 1
        panel.add(self.mode_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 3
        panel.add(padding_label, constraints)
        constraints.gridx = 1
        panel.add(self.padding_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 4
        panel.add(format_label, constraints)
        constraints.gridx = 1
        panel.add(self.format_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 5
        panel.add(key_format_label, constraints)
        constraints.gridx = 1
        panel.add(self.key_format_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 6
        panel.add(iv_format_label, constraints)
        constraints.gridx = 1
        panel.add(self.iv_format_combo, constraints)

        constraints.gridx = 0
        constraints.gridy = 7
        panel.add(key_label, constraints)
        constraints.gridx = 1
        panel.add(self.key_field, constraints)

        constraints.gridx = 0
        constraints.gridy = 8
        panel.add(iv_label, constraints)
        constraints.gridx = 1
        panel.add(self.iv_field, constraints)

        # Align buttons in a separate row
        button_panel = JPanel()
        button_panel.add(save_button)
        button_panel.add(new_profile_button)
        button_panel.add(delete_profile_button)
        button_panel.add(reset_button)

        constraints.gridx = 0
        constraints.gridy = 9
        constraints.gridwidth = 2
        panel.add(button_panel, constraints)

        self.settings_frame.add(panel, constraints)
        self.settings_frame.pack()  # Adjust size based on components
        self.settings_frame.setResizable(False)  # Fixed size
        self.settings_frame.setVisible(True)

        self.load_profile(self.current_profile)

    def load_profile(self, profile_name):
        if profile_name:
            profile = self.settings[profile_name]
            self.encryption_combo.setSelectedItem(profile["encryption"])
            self.mode_combo.setSelectedItem(profile["mode"])
            self.padding_combo.setSelectedItem(profile["padding"])
            self.format_combo.setSelectedItem(profile["format"])
            self.key_format_combo.setSelectedItem(profile["key_format"])
            self.iv_format_combo.setSelectedItem(profile["iv_format"])
            self.key_field.setText(profile["key"])
            self.iv_field.setText(profile["iv"])
            self.current_profile = profile_name

    def save_settings(self, frame):
        profile_name = self.current_profile
        self.settings[profile_name] = {
            "encryption": self.encryption_combo.getSelectedItem(),
            "mode": self.mode_combo.getSelectedItem(),
            "padding": self.padding_combo.getSelectedItem(),
            "format": self.format_combo.getSelectedItem(),
            "key_format": self.key_format_combo.getSelectedItem(),
            "iv_format": self.iv_format_combo.getSelectedItem(),
            "key": self.key_field.getText(),
            "iv": self.iv_field.getText()
        }
        self._callbacks.saveExtensionSetting("settings", json.dumps(self.settings))
        frame.dispose()
        self.settings_frame = None
        JOptionPane.showMessageDialog(None, "Profile saved successfully!")

    def reset_settings(self):
        # Clear saved settings
        self._callbacks.saveExtensionSetting("settings", None)
        self._callbacks.saveExtensionSetting("user_jar_path", None)
        self._callbacks.saveExtensionSetting("java_path", None)

        # Reset to default paths
        self.user_jar_path = self.default_jar_path
        self.java_path = "java"  # Default Java path

        # Reset other settings to default
        self.settings = {
            "Default": {
                "encryption": "AES",
                "mode": "CBC",
                "padding": "PKCS5Padding",
                "format": "base64",
                "key_format": "plain",
                "iv_format": "plain",
                "key": "d41d8cd98f00b204e9800998ecf8427e",  # md5('')
                "iv": "d41d8cd98f00b204"  # md5('')[:16]
            }
        }
        self.current_profile = "Default"
        
        JOptionPane.showMessageDialog(None, "Settings have been reset to default.")
        self.show_settings()  # Reload settings UI to reflect default values
        
    def new_profile(self):
        profile_name = JOptionPane.showInputDialog("Enter new profile name:")
        if profile_name and profile_name not in self.settings:
            self.settings[profile_name] = {
                "encryption": "AES",
                "mode": "CBC",
                "padding": "PKCS5Padding",
                "format": "base64",
                "key_format": "plain",
                "iv_format": "plain",
                "key": "",
                "iv": ""
            }
            self.profile_combo.addItem(profile_name)
            self.profile_combo.setSelectedItem(profile_name)

    def delete_profile(self):
        profile_name = self.profile_combo.getSelectedItem()
        if profile_name and profile_name != "Default":
            del self.settings[profile_name]
            self.profile_combo.removeItem(profile_name)
            if profile_name == self.current_profile:
                self.load_profile("Default")

    def process_selected_text(self, invocation, action):
        selected_messages = invocation.getSelectedMessages()
        if selected_messages:
            for message in selected_messages:
                selected_text = self.get_selected_text(message, invocation)
                if selected_text:
                    processed_text = self.run_utility(selected_text, action)
                    self.handle_processed_text(message, invocation, processed_text)

    def get_selected_text(self, message, invocation):
        selection_bounds = invocation.getSelectionBounds()
        if selection_bounds:
            if invocation.getInvocationContext() in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
                request = message.getRequest()
                selected_text = request[selection_bounds[0]:selection_bounds[1]]
            elif invocation.getInvocationContext() in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
                response = message.getResponse()
                selected_text = response[selection_bounds[0]:selection_bounds[1]]
            return selected_text.tostring()

    def prettify_json(self, text):
        try:
            json_obj = json.loads(text)
            prettified_json = json.dumps(json_obj, indent=4)
            return prettified_json
        except ValueError:
            return text

    def handle_processed_text(self, message, invocation, processed_text):
        context = invocation.getInvocationContext()
        if invocation.getToolFlag() == self._callbacks.TOOL_REPEATER and context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            self.replace_selected_text(message, invocation, processed_text)
        elif invocation.getToolFlag() == self._callbacks.TOOL_PROXY and context in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE]:
            self.replace_selected_text(message, invocation, processed_text)
        else:
            prettified_text = self.prettify_json(processed_text)
            self.show_popup(prettified_text)

    def replace_selected_text(self, message, invocation, new_text):
        selection_bounds = invocation.getSelectionBounds()
        if selection_bounds:
            new_text_bytes = array.array('b', new_text.encode('utf-8'))  # Convert new_text to byte array
            if invocation.getInvocationContext() in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
                request = message.getRequest()
                new_request = request[:selection_bounds[0]] + new_text_bytes + request[selection_bounds[1]:]
                message.setRequest(new_request)
            elif invocation.getInvocationContext() in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
                response = message.getResponse()
                new_response = response[:selection_bounds[0]] + new_text_bytes + response[selection_bounds[1]:]
                message.setResponse(new_response)

    def show_popup(self, text):
        message_editor = self._callbacks.createMessageEditor(self, False)
        message_editor.setMessage(text.encode('utf-8'), False)        
        frame = JFrame("Converted Text")
        frame.setSize(600, 200)
        frame.setLayout(BorderLayout())        
        frame.add(message_editor.getComponent(), BorderLayout.CENTER)
        frame.setVisible(True)

    def run_utility(self, text, action):
        text = text.replace("\/", "/")
        result_queue = LinkedBlockingQueue()

        def utility_thread():
            try:
                command = [
                    self.java_path, "-jar", self.user_jar_path,  # Use updated paths
                    action,  # 'enc' for encryption, 'dec' for decryption
                    self.settings[self.current_profile]["encryption"],
                    text,
                    self.settings[self.current_profile]["key"],
                    self.settings[self.current_profile]["iv"],
                    self.settings[self.current_profile]["mode"],
                    self.settings[self.current_profile]["padding"],
                    self.settings[self.current_profile]["key_format"],
                    "" if self.settings[self.current_profile]["iv_format"] == "N/A" else self.settings[self.current_profile]["iv_format"],
                    self.settings[self.current_profile]["format"]
                ]

                print("[+] Executing system command - {}".format(command))
                
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = process.communicate()
                if process.returncode == 0:
                    result = stdout.strip().decode('utf-8')
                else:
                    result = stderr.decode('utf-8')
            except Exception as e:
                result = str(e)

            result_queue.put(result)

        thread = threading.Thread(target=utility_thread)
        thread.start()
        thread.join()

        return result_queue.take()
