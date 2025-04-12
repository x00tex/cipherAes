from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation, IMessageEditorTab, IMessageEditorTabFactory
from java.util import ArrayList, Base64
from javax.swing import JTextArea, JScrollPane, JMenuItem, JFrame, JPanel, JLabel, JComboBox, JTextField, JButton, JOptionPane, BorderFactory, JFileChooser, Timer, ImageIcon
from java.awt import GridBagLayout, GridBagConstraints, Insets, BorderLayout, Color, Cursor, Image
from java.util.concurrent import LinkedBlockingQueue
from java.io import File, ByteArrayInputStream
from javax.imageio import ImageIO
import subprocess
import threading
import array
import json
import os

class BurpExtender(IBurpExtender, IContextMenuFactory, IMessageEditorTabFactory):
    VERSION = "v2.0.0"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("CipherAes")
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerMessageEditorTabFactory(self)

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

    def createNewInstance(self, controller, editable):
        return CipherTab(self, controller, editable)
    
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

        # Create the warning button
        warning_button = JButton("WARNING!", actionPerformed=lambda x: self.show_warning_message())
        warning_button.setBackground(Color.RED)
        warning_button.setForeground(Color.BLACK)

        # Timer for blinking effect
        def toggle_color(event):
            current_color = warning_button.getBackground()
            new_color = Color.RED if current_color != Color.RED else Color.GRAY
            warning_button.setBackground(new_color)

        timer = Timer(500, toggle_color)
        timer.start()

        # Add components to the panel
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

        constraints.gridy = 3
        constraints.gridwidth = 1
        panel.add(warning_button, constraints)

        constraints.gridx = 2
        version_label = JLabel(self.VERSION)
        panel.add(version_label, constraints)

        frame.add(panel)
        frame.pack()
        frame.setResizable(False)
        frame.setVisible(True)

    def show_warning_message(self):
        JOptionPane.showMessageDialog(None, 
            "Any input in these settings will be passed to system commands via subprocess.Popen().\n"
            "Ensure inputs are safe as they are directly inserted into system commands.\n"
            "Executed commands can be viewed in the extension logs.",
            "Warning", JOptionPane.WARNING_MESSAGE)

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

        reset_button = JButton("Reset All", actionPerformed=lambda x: self.reset_settings())
        reset_button.setToolTipText("Reset settings and profiles to default")

        import_button = JButton("Import Profiles", actionPerformed=lambda x: self.import_settings())
        import_button.setToolTipText("Import profiles to a json file")

        export_button = JButton("Export Profiles", actionPerformed=lambda x: self.export_settings())
        export_button.setToolTipText("Export profiles from a json file")

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

        first_row_button_panel = JPanel()
        first_row_button_panel.add(save_button)
        first_row_button_panel.add(new_profile_button)
        first_row_button_panel.add(delete_profile_button)
        first_row_button_panel.add(reset_button)

        second_row_button_panel = JPanel()
        second_row_button_panel.add(import_button)
        second_row_button_panel.add(export_button)

        constraints.gridx = 0
        constraints.gridy = 9
        constraints.gridwidth = 2
        panel.add(first_row_button_panel, constraints)

        constraints.gridx = 0
        constraints.gridy = 10
        constraints.gridwidth = 2
        panel.add(second_row_button_panel, constraints)
        
        self.settings_frame.add(panel, constraints)
        self.settings_frame.pack()  # Adjust size based on components
        self.settings_frame.setResizable(False)  # Fixed size
        self.settings_frame.setVisible(True)

        self.load_profile(self.current_profile)

    def export_settings(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Profiles As")
        chooser.setSelectedFile(File("profiles.json"))
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if os.path.exists(file_path):
                overwrite = JOptionPane.showConfirmDialog(None, "File already exists. Overwrite?", "Confirm", JOptionPane.YES_NO_OPTION)
                if overwrite != JOptionPane.YES_OPTION:
                    return
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.settings, f, indent=4)
                JOptionPane.showMessageDialog(None, "Settings exported successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Failed to export profiles: {}".format(e), "Error", JOptionPane.ERROR_MESSAGE)

    def import_settings(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import Profiles")
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(file_path, 'r') as f:
                    imported_settings = json.load(f)
                if not isinstance(imported_settings, dict):
                    raise ValueError("Invalid format.")
                self.settings.update(imported_settings)
                JOptionPane.showMessageDialog(None, "Profiles imported successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)
                self.show_settings()
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Failed to import profiles: {}".format(e), "Error", JOptionPane.ERROR_MESSAGE)
                
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
        if not isinstance(text, str):
            raise ValueError("Invalid input type")
        
        allowed_actions = {"enc", "dec"}
        if action not in allowed_actions:
            raise ValueError("Invalid action")

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

                try:
                    print("[+] Executing system command - {}".format(' '.join('"{}"'.format(x) if i in [5, 6, 7] else x for i, x in enumerate(command))))
                except Exception as e:
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

class CipherTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._controller = controller
        self._helpers = extender._helpers
        
        self._panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(5, 5, 5, 5)
        
        # quick profile switching
        button_panel_top = JPanel()
        self.profile_label = JLabel("Profile:")
        button_panel_top.add(self.profile_label)

        self.profile_combo = JComboBox(self._extender.settings.keys())
        self.profile_combo.setSelectedItem(self._extender.current_profile)
        self.profile_combo.addActionListener(lambda e: self.load_profile(self.profile_combo.getSelectedItem()))
        button_panel_top.add(self.profile_combo)

        self.refresh_button = JButton("Refresh", actionPerformed=lambda e: self.refresh_profiles)
        self.refresh_button.setToolTipText("Refresh profile list")
        button_panel_top.add(self.refresh_button)

        # Note: fancy refresh button, but disabled for performance.
        # refreshIconB64 = "iVBORw0KGgoAAAANSUhEUgAAABEAAAARCAMAAAAMs7fIAAAASFBMVEVHcEwjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyM" \
        #                  "jIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyNK7aojAAAAF3RSTlMAFgea9AP6UEjS3m" \
        #                  "cMtKlYkCUgO30ygBjkAfgAAACESURBVBjTdY9HAoQwDANxXNIJbfH/f7qkwC2+eVwkLcukGA7ghdPbG7v64FdbMnQAK" \
        #                  "CokSoHOvoFK6H4OSbU0YoUi14GoXo1silxX7+xD7G/cPgQSmIkXA2mMdtfVY/D5roxRt0YuVcGHcCSxjRT9/GA/Px+v" \
        #                  "zbPgGyKXkevTTjyyT+oPGw8FMYkeJFwAAAAASUVORK5CYII="
        # self.refresh_button = self._createImageButton(refreshIconB64, "Refresh profile list", self.refresh_profiles)
        # button_panel_top.add(self.refresh_button)

        constraints.gridx = 0
        constraints.gridy = 0
        constraints.fill = GridBagConstraints.HORIZONTAL
        self._panel.add(button_panel_top, constraints)

        # Input field with scroll and line wrap
        self._input_area = JTextArea(5, 30)
        self._input_area.setLineWrap(True)
        self._input_area.setWrapStyleWord(True)
        input_scroll = JScrollPane(self._input_area)
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.gridwidth = 3
        constraints.fill = GridBagConstraints.BOTH
        constraints.weightx = 1.0
        constraints.weighty = 0.5
        self._panel.add(input_scroll, constraints)
        
        # Button Panel
        button_panel = JPanel()
        self._encode_button = JButton("Encrypt", actionPerformed=self.encrypt)
        button_panel.add(self._encode_button)
        
        self._decode_button = JButton("Decrypt", actionPerformed=self.decrypt)
        button_panel.add(self._decode_button)
        
        self._clear_button = JButton("Clear", actionPerformed=self.clear)
        button_panel.add(self._clear_button)
        
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 3
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.weightx = 0
        constraints.weighty = 0
        self._panel.add(button_panel, constraints)

        # Output field with scroll and line wrap
        self._output_area = JTextArea(5, 30)
        self._output_area.setEditable(False)
        self._output_area.setLineWrap(True)
        self._output_area.setWrapStyleWord(True)
        output_scroll = JScrollPane(self._output_area)
        constraints.gridx = 0
        constraints.gridy = 3
        constraints.gridwidth = 3
        constraints.fill = GridBagConstraints.BOTH
        constraints.weightx = 1.0
        constraints.weighty = 0.5
        self._panel.add(output_scroll, constraints)

    def load_profile(self, profile_name):
        self._extender.current_profile = profile_name

    def refresh_profiles(self, event):
        self.profile_combo.removeAllItems()
        for profile in self._extender.settings.keys():
            self.profile_combo.addItem(profile)
        self.profile_combo.setSelectedItem(self._extender.current_profile)

    # def _createImageButton(self, base64String, tooltip, action):
    #     try:
    #         imageBytes = Base64.getDecoder().decode(base64String)
    #         inputStream = ByteArrayInputStream(imageBytes)
    #         initialImg = ImageIO.read(inputStream)
    #         width = 17
    #         height = 17
    #         scaledImg = initialImg.getScaledInstance(width, height, Image.SCALE_SMOOTH)
    #         button = JButton(ImageIcon(scaledImg), actionPerformed=action)
    #         button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
    #         button.setToolTipText(tooltip)
    #         return button
    #     except Exception as e:
    #         self.debug("Error creating image button: {}".format(e), type='err')
    #         return JButton()
            
    def getTabCaption(self):
        return "CipherAes"
    
    def getUiComponent(self):
        return self._panel
    
    def isEnabled(self, content, isRequest):
        return True
    
    def setMessage(self, content, isRequest):
        pass
    
    def getMessage(self):
        return None
    
    def isModified(self):
        return False
    
    def getSelectedData(self):
        return None
    
    def encrypt(self, event):
        input_text = self._input_area.getText().encode('utf-8')
        minified_text = self.minify_json(input_text)
        try:
            encrypted_text = self._extender.run_utility(minified_text, "enc")
            self._output_area.setText(encrypted_text)
        except Exception as e:
            self._output_area.setText("Error encrypting text: " + str(e))
    
    def decrypt(self, event):
        input_text = self._input_area.getText().encode('utf-8')
        try:
            decrypted_text = self._extender.run_utility(input_text, "dec")
            prettified_text = self.prettify_json(decrypted_text)
            self._output_area.setText(prettified_text)
        except Exception as e:
            self._output_area.setText("Error decrypting text: " + str(e))

    def prettify_json(self, text):
        try:
            json_obj = json.loads(text)
            prettified_json = json.dumps(json_obj, indent=4)
            return prettified_json
        except ValueError:
            return text

    def minify_json(self, text):
        try:
            json_obj = json.loads(text)
            minified_json = json.dumps(json_obj, separators=(',', ':'))
            return minified_json
        except ValueError:
            return text
    
    def clear(self, event):
        self._input_area.setText("")
        self._output_area.setText("")
