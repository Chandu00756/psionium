import 'package:flutter/material.dart';
import 'package:syncfusion_flutter_charts/charts.dart';

class BillingScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          "Billing & Subscriptions",
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
              // Usage Statistics Section
              _buildUsageStatisticsSection(context),
              SizedBox(height: 20),

              // Subscription Plans Section
              _buildSubscriptionPlansSection(context),
              SizedBox(height: 20),

              // Payment History Section
              _buildPaymentHistorySection(context),
              SizedBox(height: 20),

              // AI-Driven Insights Section
              _buildInsightsSection(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildUsageStatisticsSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Usage Statistics",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            SfCartesianChart(
              primaryXAxis: CategoryAxis(),
              series: <ChartSeries>[
                ColumnSeries<ChartData, String>(
                  dataSource: [
                    ChartData('Storage', 75),
                    ChartData('Encryption', 50),
                    ChartData('Bandwidth', 30),
                  ],
                  xValueMapper: (ChartData data, _) => data.category,
                  yValueMapper: (ChartData data, _) => data.value,
                  color: Colors.green,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSubscriptionPlansSection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Subscription Plans",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _buildPlanCard("Free", "\$0/month", ["10 GB Storage", "Basic Encryption"], Colors.blue),
                _buildPlanCard("Premium", "\$10/month", ["100 GB Storage", "Advanced Encryption", "AI Insights"], Colors.green),
                _buildPlanCard("Enterprise", "\$50/month", ["Unlimited Storage", "Quantum Encryption", "Priority Support"], Colors.orange),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPlanCard(String plan, String price, List<String> features, Color color) {
    return Card(
      color: Colors.grey[800],
      elevation: 4,
      child: InkWell(
        onTap: () {
          // Handle plan selection
        },
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                plan,
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: color),
              ),
              SizedBox(height: 10),
              Text(
                price,
                style: TextStyle(fontSize: 16, color: Colors.white),
              ),
              SizedBox(height: 10),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: features.map((feature) {
                  return Text(
                    "• $feature",
                    style: TextStyle(fontSize: 14, color: Colors.white),
                  );
                }).toList(),
              ),
              SizedBox(height: 10),
              ElevatedButton(
                onPressed: () {
                  // Handle upgrade/downgrade
                },
                child: Text("Select Plan", style: TextStyle(color: Colors.black)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: color,
                  padding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPaymentHistorySection(BuildContext context) {
    return Card(
      color: Colors.grey[900],
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Payment History",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: Colors.green),
            ),
            SizedBox(height: 10),
            ListView.builder(
              shrinkWrap: true,
              physics: NeverScrollableScrollPhysics(),
              itemCount: 5,
              itemBuilder: (context, index) {
                return ListTile(
                  leading: Icon(Icons.receipt, color: Colors.green),
                  title: Text("Invoice #${index + 1}", style: TextStyle(color: Colors.white)),
                  subtitle: Text("\$10.00 - 2023-10-0${index + 1}", style: TextStyle(color: Colors.grey)),
                  trailing: IconButton(
                    icon: Icon(Icons.download, color: Colors.white),
                    onPressed: () {
                      // Download invoice
                    },
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInsightsSection(BuildContext context) {
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
            ListTile(
              leading: Icon(Icons.analytics, color: Colors.green),
              title: Text("Optimize Storage Usage", style: TextStyle(color: Colors.white)),
              subtitle: Text("Switch to Premium plan to save \$5/month", style: TextStyle(color: Colors.grey)),
              trailing: IconButton(
                icon: Icon(Icons.arrow_forward, color: Colors.white),
                onPressed: () {
                  // Handle optimization
                },
              ),
            ),
            ListTile(
              leading: Icon(Icons.notifications, color: Colors.green),
              title: Text("Usage Alert", style: TextStyle(color: Colors.white)),
              subtitle: Text("You've used 90% of your storage", style: TextStyle(color: Colors.grey)),
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
  final String category;
  final int value;

  ChartData(this.category, this.value);
}