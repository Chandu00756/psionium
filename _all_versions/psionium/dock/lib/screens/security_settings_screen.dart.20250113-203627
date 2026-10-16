import 'package:flutter/material.dart';

class SecuritySettingsScreen extends StatefulWidget {
  @override
  _SecuritySettingsScreenState createState() => _SecuritySettingsScreenState();
}

class _SecuritySettingsScreenState extends State<SecuritySettingsScreen> {
  bool _quantumResistantEncryption = true;
  bool _twoFactorAuthentication = false;
  String _encryptionAlgorithm = "AES-256";
  String _retentionPolicy = "30 days";
  bool _automaticDeletion = false;
  bool _blockchainIntegration = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          "Security Settings",
          style: TextStyle(color: Colors.green, fontWeight: FontWeight.bold),
        ),
        backgroundColor: Colors.black,
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Encryption Settings
              _buildSectionHeader("Encryption Settings"),
              _buildToggleSetting(
                "Quantum-Resistant Encryption",
                _quantumResistantEncryption,
                (value) {
                  setState(() {
                    _quantumResistantEncryption = value;
                  });
                },
              ),
              _buildDropdownSetting(
                "Encryption Algorithm",
                _encryptionAlgorithm,
                ["AES-256", "Ring-LWE", "ChaCha20"],
                (value) {
                  setState(() {
                    _encryptionAlgorithm = value!;
                  });
                },
              ),
              _buildSliderSetting(
                "Key Rotation Interval",
                "30 days",
                (value) {
                  setState(() {
                    // Update key rotation interval
                  });
                },
              ),
              SizedBox(height: 20),

              // Access Control
              _buildSectionHeader("Access Control"),
              _buildButtonSetting(
                "Manage Roles",
                Icons.people,
                () {
                  // Navigate to role management screen
                },
              ),
              _buildButtonSetting(
                "View Activity Logs",
                Icons.history,
                () {
                  // Navigate to activity logs screen
                },
              ),
              SizedBox(height: 20),

              // Two-Factor Authentication
              _buildSectionHeader("Two-Factor Authentication"),
              _buildToggleSetting(
                "Enable 2FA",
                _twoFactorAuthentication,
                (value) {
                  setState(() {
                    _twoFactorAuthentication = value;
                  });
                },
              ),
              _buildDropdownSetting(
                "Authentication Method",
                "Authenticator App",
                ["SMS", "Email", "Authenticator App"],
                (value) {
                  setState(() {
                    // Update authentication method
                  });
                },
              ),
              _buildButtonSetting(
                "Generate Backup Codes",
                Icons.security,
                () {
                  // Generate backup codes
                },
              ),
              SizedBox(height: 20),

              // Data Retention
              _buildSectionHeader("Data Retention"),
              _buildDropdownSetting(
                "Retention Policy",
                _retentionPolicy,
                ["30 days", "1 year", "Indefinite"],
                (value) {
                  setState(() {
                    _retentionPolicy = value!;
                  });
                },
              ),
              _buildToggleSetting(
                "Automatic Deletion",
                _automaticDeletion,
                (value) {
                  setState(() {
                    _automaticDeletion = value;
                  });
                },
              ),
              _buildButtonSetting(
                "Archive Old Data",
                Icons.archive,
                () {
                  // Archive old data
                },
              ),
              SizedBox(height: 20),

              // Advanced Features
              _buildSectionHeader("Advanced Features"),
              _buildToggleSetting(
                "AI-Driven Threat Detection",
                true,
                (value) {
                  setState(() {
                    // Toggle threat detection
                  });
                },
              ),
              _buildToggleSetting(
                "Blockchain Integration",
                _blockchainIntegration,
                (value) {
                  setState(() {
                    _blockchainIntegration = value;
                  });
                },
              ),
              _buildButtonSetting(
                "Define Custom Rules",
                Icons.rule,
                () {
                  // Navigate to custom rules screen
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Text(
      title,
      style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
    );
  }

  Widget _buildToggleSetting(String label, bool value, Function(bool) onChanged) {
    return ListTile(
      title: Text(label, style: TextStyle(color: Colors.white)),
      trailing: Switch(
        value: value,
        onChanged: onChanged,
        activeColor: Colors.green,
      ),
    );
  }

  Widget _buildDropdownSetting(String label, String value, List<String> options, Function(String?) onChanged) {
    return ListTile(
      title: Text(label, style: TextStyle(color: Colors.white)),
      trailing: DropdownButton<String>(
        value: value,
        onChanged: onChanged,
        items: options.map((String option) {
          return DropdownMenuItem<String>(
            value: option,
            child: Text(option, style: TextStyle(color: Colors.black)),
          );
        }).toList(),
        dropdownColor: Colors.grey[900],
        style: TextStyle(color: Colors.white),
      ),
    );
  }

  Widget _buildSliderSetting(String label, String value, Function(double) onChanged) {
    return ListTile(
      title: Text(label, style: TextStyle(color: Colors.white)),
      subtitle: Text(value, style: TextStyle(color: Colors.grey)),
      trailing: Slider(
        value: 0.5, // Example value
        onChanged: onChanged,
        activeColor: Colors.green,
      ),
    );
  }

  Widget _buildButtonSetting(String label, IconData icon, VoidCallback onPressed) {
    return ListTile(
      title: Text(label, style: TextStyle(color: Colors.white)),
      trailing: IconButton(
        icon: Icon(icon, color: Colors.green),
        onPressed: onPressed,
      ),
    );
  }
}