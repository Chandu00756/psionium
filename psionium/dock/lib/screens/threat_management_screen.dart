import 'package:flutter/material.dart';
import 'package:syncfusion_flutter_charts/charts.dart';

class ThreatManagementScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          "Threat Management",
          style: TextStyle(color: Colors.red, fontWeight: FontWeight.bold),
        ),
        backgroundColor: Colors.black,
        actions: [
          IconButton(
            icon: Icon(Icons.search, color: Colors.red),
            onPressed: () {
              // Open global search
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
              // Threat Map Section
              _buildThreatMapSection(context),
              SizedBox(height: 20),

              // Risk Dashboard Section
              _buildRiskDashboardSection(context),
              SizedBox(height: 20),

              // Threat Timeline Section
              _buildThreatTimelineSection(context),
              SizedBox(height: 20),

              // Real-Time Alerts Section
              _buildRealTimeAlertsSection(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildThreatMapSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Threat Map",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.red),
            ),
            SizedBox(height: 10),
            // Placeholder for threat map
            Container(
              height: 200,
              decoration: BoxDecoration(
                color: Colors.grey[800],
                borderRadius: BorderRadius.circular(10),
              ),
              child: Center(
                child: Text(
                  "Threat Map Visualization",
                  style: TextStyle(color: Colors.white),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRiskDashboardSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Risk Dashboard",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.red),
            ),
            SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: _buildRiskChart(),
                ),
                SizedBox(width: 10),
                Expanded(
                  child: _buildRiskMetrics(),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRiskChart() {
    return SfCartesianChart(
      primaryXAxis: CategoryAxis(),
      series: <ChartSeries>[
        ColumnSeries<ChartData, String>(
          dataSource: [
            ChartData('Mon', 35),
            ChartData('Tue', 28),
            ChartData('Wed', 34),
            ChartData('Thu', 32),
            ChartData('Fri', 40),
          ],
          xValueMapper: (ChartData data, _) => data.day,
          yValueMapper: (ChartData data, _) => data.usage,
          color: Colors.red,
        ),
      ],
    );
  }

  Widget _buildRiskMetrics() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          "Risk Metrics",
          style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
        ),
        SizedBox(height: 10),
        ListTile(
          leading: Icon(Icons.warning, color: Colors.red),
          title: Text("High Risk Threats", style: TextStyle(color: Colors.white)),
          subtitle: Text("12 detected", style: TextStyle(color: Colors.grey)),
        ),
        ListTile(
          leading: Icon(Icons.timeline, color: Colors.orange),
          title: Text("Medium Risk Threats", style: TextStyle(color: Colors.white)),
          subtitle: Text("24 detected", style: TextStyle(color: Colors.grey)),
        ),
        ListTile(
          leading: Icon(Icons.check_circle, color: Colors.green),
          title: Text("Low Risk Threats", style: TextStyle(color: Colors.white)),
          subtitle: Text("8 detected", style: TextStyle(color: Colors.grey)),
        ),
      ],
    );
  }

  Widget _buildThreatTimelineSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Threat Timeline",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.red),
            ),
            SizedBox(height: 10),
            ListTile(
              leading: Icon(Icons.warning, color: Colors.red),
              title: Text("Unauthorized access detected", style: TextStyle(color: Colors.white)),
              subtitle: Text("10 minutes ago", style: TextStyle(color: Colors.grey)),
            ),
            ListTile(
              leading: Icon(Icons.timeline, color: Colors.orange),
              title: Text("Data tampering detected", style: TextStyle(color: Colors.white)),
              subtitle: Text("2 hours ago", style: TextStyle(color: Colors.grey)),
            ),
            ListTile(
              leading: Icon(Icons.check_circle, color: Colors.green),
              title: Text("Low-risk anomaly detected", style: TextStyle(color: Colors.white)),
              subtitle: Text("5 hours ago", style: TextStyle(color: Colors.grey)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRealTimeAlertsSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Real-Time Alerts",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.red),
            ),
            SizedBox(height: 10),
            ListTile(
              leading: Icon(Icons.warning, color: Colors.red),
              title: Text("High-risk threat detected", style: TextStyle(color: Colors.white)),
              subtitle: Text("Just now", style: TextStyle(color: Colors.grey)),
              trailing: IconButton(
                icon: Icon(Icons.close, color: Colors.white),
                onPressed: () {
                  // Dismiss alert
                },
              ),
            ),
            ListTile(
              leading: Icon(Icons.timeline, color: Colors.orange),
              title: Text("Medium-risk anomaly detected", style: TextStyle(color: Colors.white)),
              subtitle: Text("5 minutes ago", style: TextStyle(color: Colors.grey)),
              trailing: IconButton(
                icon: Icon(Icons.close, color: Colors.white),
                onPressed: () {
                  // Dismiss alert
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class ChartData {
  final String day;
  final int usage;

  ChartData(this.day, this.usage);
}