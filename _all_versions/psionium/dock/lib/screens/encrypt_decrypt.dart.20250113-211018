import 'package:flutter/material.dart';
import 'package:syncfusion_flutter_charts/charts.dart';

class EncryptionScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          "Encryption/Decryption",
          style: TextStyle(color: Colors.green, fontWeight: FontWeight.bold),
        ),
        backgroundColor: Colors.black,
        actions: [
          IconButton(
            icon: Icon(Icons.settings, color: Colors.green),
            onPressed: () {
              // Navigate to encryption settings
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Encryption Section
              _buildEncryptionSection(context),
              SizedBox(height: 20),

              // Decryption Section
              _buildDecryptionSection(context),
              SizedBox(height: 20),

              // Key Management Section
              _buildKeyManagementSection(context),
              SizedBox(height: 20),

              // Quantum-Resilience Section
              _buildQuantumResilienceSection(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildEncryptionSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Encrypt Files",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _buildActionButton(Icons.lock, "Encrypt File", () {
                  // Handle encrypt file
                }),
                _buildActionButton(Icons.lock, "Batch Encrypt", () {
                  // Handle batch encrypt
                }),
                _buildActionButton(Icons.settings, "Custom Encryption", () {
                  // Handle custom encryption
                }),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDecryptionSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Decrypt Files",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _buildActionButton(Icons.lock_open, "Decrypt File", () {
                  // Handle decrypt file
                }),
                _buildActionButton(Icons.lock_open, "Batch Decrypt", () {
                  // Handle batch decrypt
                }),
                _buildActionButton(Icons.verified_user, "Verify Key", () {
                  // Handle verify key
                }),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildKeyManagementSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Key Management",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _buildActionButton(Icons.vpn_key, "Generate Key", () {
                  // Handle generate key
                }),
                _buildActionButton(Icons.storage, "Store Key", () {
                  // Handle store key
                }),
                _buildActionButton(Icons.share, "Share Key", () {
                  // Handle share key
                }),
                _buildActionButton(Icons.autorenew, "Rotate Key", () {
                  // Handle rotate key
                }),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildQuantumResilienceSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Quantum-Resilient Encryption",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _buildActionButton(Icons.security, "Enable Quantum-Resilience", () {
                  // Handle enable quantum-resilience
                }),
                _buildActionButton(Icons.analytics, "View Security Insights", () {
                  // Handle view security insights
                }),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionButton(IconData icon, String label, VoidCallback onPressed) {
    return ElevatedButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, color: Colors.black),
      label: Text(label, style: TextStyle(color: Colors.black)),
      style: ElevatedButton.styleFrom(
        backgroundColor: Colors.green,
        padding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      ),
    );
  }
}