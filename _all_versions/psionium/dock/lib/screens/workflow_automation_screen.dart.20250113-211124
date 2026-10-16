import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';

class WorkflowAutomationScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          "Workflow Automation",
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
              // Custom Workflows Section
              _buildCustomWorkflowsSection(context),
              SizedBox(height: 20),

              // Scheduled Tasks Section
              _buildScheduledTasksSection(context),
              SizedBox(height: 20),

              // Command Execution Section
              _buildCommandExecutionSection(context),
              SizedBox(height: 20),

              // API Integration Section
              _buildApiIntegrationSection(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildCustomWorkflowsSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Custom Workflows",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Create and manage custom workflows using a drag-and-drop interface.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            ElevatedButton(
              onPressed: () {
                // Open workflow editor
              },
              child: Text("Create Workflow", style: TextStyle(color: Colors.black)),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.green,
                padding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              ),
            ),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideX(begin: -0.1);
  }

  Widget _buildScheduledTasksSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Scheduled Tasks",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Schedule tasks to run automatically at specific times or intervals.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            ListTile(
              leading: Icon(Icons.schedule, color: Colors.green),
              title: Text("Daily Backup", style: TextStyle(color: Colors.white)),
              subtitle: Text("Runs every day at 2:00 AM", style: TextStyle(color: Colors.grey)),
              trailing: Switch(
                value: true,
                onChanged: (value) {
                  // Toggle task
                },
                activeColor: Colors.green,
              ),
            ),
            ListTile(
              leading: Icon(Icons.schedule, color: Colors.green),
              title: Text("Weekly Report", style: TextStyle(color: Colors.white)),
              subtitle: Text("Runs every Monday at 9:00 AM", style: TextStyle(color: Colors.grey)),
              trailing: Switch(
                value: false,
                onChanged: (value) {
                  // Toggle task
                },
                activeColor: Colors.green,
              ),
            ),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideX(begin: 0.1);
  }

  Widget _buildCommandExecutionSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Command Execution",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Execute shell commands directly from the Dock.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            TextField(
              decoration: InputDecoration(
                hintText: "Enter command (e.g., ls -l)",
                border: OutlineInputBorder(),
                filled: true,
                fillColor: Colors.grey[800],
                hintStyle: TextStyle(color: Colors.grey),
              ),
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            ElevatedButton(
              onPressed: () {
                // Execute command
              },
              child: Text("Execute", style: TextStyle(color: Colors.black)),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.green,
                padding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              ),
            ),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideY(begin: 0.1);
  }

  Widget _buildApiIntegrationSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "API Integration",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Text(
              "Integrate with external APIs for advanced automation.",
              style: TextStyle(color: Colors.white),
            ),
            SizedBox(height: 10),
            ListTile(
              leading: Icon(Icons.cloud, color: Colors.green),
              title: Text("Cloud Storage", style: TextStyle(color: Colors.white)),
              subtitle: Text("Connect to Google Drive, Dropbox, etc.", style: TextStyle(color: Colors.grey)),
              trailing: IconButton(
                icon: Icon(Icons.settings, color: Colors.green),
                onPressed: () {
                  // Configure API
                },
              ),
            ),
            ListTile(
              leading: Icon(Icons.code, color: Colors.green),
              title: Text("Webhooks", style: TextStyle(color: Colors.white)),
              subtitle: Text("Trigger workflows using webhooks.", style: TextStyle(color: Colors.grey)),
              trailing: IconButton(
                icon: Icon(Icons.settings, color: Colors.green),
                onPressed: () {
                  // Configure webhooks
                },
              ),
            ),
          ],
        ),
      ),
    ).animate().fadeIn(duration: 500.ms).slideY(begin: -0.1);
  }
}