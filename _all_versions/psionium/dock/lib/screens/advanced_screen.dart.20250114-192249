import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';

class AdvancedFeaturesScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          "Advanced Features",
          style: TextStyle(color: Colors.green, fontWeight: FontWeight.bold),
        ),
        backgroundColor: Colors.black,
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Quantum-Resilient Vaults
              _buildQuantumResilientVaultsSection(context),
              SizedBox(height: 20),

              // Blockchain Integration
              _buildBlockchainIntegrationSection(context),
              SizedBox(height: 20),

              // AI-Driven Insights
              _buildAIDrivenInsightsSection(context),
              SizedBox(height: 20),

              // Multi-Device Sync
              _buildMultiDeviceSyncSection(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildQuantumResilientVaultsSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Quantum-Resilient Vaults",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Create vaults resistant to quantum attacks using cutting-edge encryption and encoding techniques.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            _buildFeatureToggle("Enable Quantum-Resistant Encryption", true),
            _buildFeatureToggle("Enable Dynamic Dimensional Encoding (DDED)", false),
            _buildFeatureToggle("Enable Quantum Key Distribution (QKD)", false),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideX(begin: -0.1, end: 0);
  }

  Widget _buildBlockchainIntegrationSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Blockchain Integration",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Use blockchain for immutable audit logs, smart contracts, and decentralized storage.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            _buildFeatureToggle("Enable Immutable Audit Logs", true),
            _buildFeatureToggle("Enable Smart Contracts", false),
            _buildFeatureToggle("Enable Decentralized Storage", false),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideX(begin: 0.1, end: 0);
  }

  Widget _buildAIDrivenInsightsSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "AI-Driven Insights",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Get insights and recommendations from AI for threat detection, usage analytics, and optimizations.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            _buildFeatureToggle("Enable Threat Detection", true),
            _buildFeatureToggle("Enable Usage Analytics", false),
            _buildFeatureToggle("Enable Recommendations", false),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideY(begin: 0.1, end: 0);
  }

  Widget _buildMultiDeviceSyncSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Multi-Device Sync",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Sync data across multiple devices securely with end-to-end encryption and offline access.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            _buildFeatureToggle("Enable End-to-End Encryption", true),
            _buildFeatureToggle("Enable Conflict Resolution", false),
            _buildFeatureToggle("Enable Offline Access", false),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideY(begin: -0.1, end: 0);
  }

  Widget _buildFeatureToggle(String label, bool value) {
    return SwitchListTile(
      title: Text(label, style: TextStyle(color: Colors.white)),
      value: value,
      onChanged: (newValue) {
        // Handle toggle
      },
      activeColor: Colors.green,
    );
  }
}